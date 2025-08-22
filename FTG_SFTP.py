import sublime
import sublime_plugin
import os
import json
import threading
import subprocess
import hashlib
import re
import tempfile

# -------------------------------
# 全局插件配置（在 Sublime User 设置中配置）
# -------------------------------
PLUGIN_SETTINGS = "FTG_SFTP.sublime-settings"
settings = sublime.load_settings(PLUGIN_SETTINGS)

WINSCP_PATH = settings.get("winscp_path")

MULTI_THREAD = settings.get("multi_thread", True)
INCREMENTAL_SYNC = settings.get("incremental_sync", True)
SHA_CHECK = settings.get("sha_check", True)

_config_cache = {}

# 全局锁，保证日志输出线程安全
output_lock = threading.Lock()

if not hasattr(subprocess, "CREATE_NO_WINDOW"):
    subprocess.CREATE_NO_WINDOW = 0x08000000

# -------------------------------
# 工具函数
# -------------------------------
def load_project_config(window, silent=False):
    project_folders = window.folders()
    if not project_folders:
        return None
    root = project_folders[0]

    if root in _config_cache:
        return _config_cache[root]

    config_path = os.path.join(root, "ftg-config.json")
    if not os.path.exists(config_path):
        if not silent:
            sublime.error_message("ftg-config.json 配置文件未找到")
        return None
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            config = json.load(f)
            _config_cache[root] = (config, root)
            return config, root
    except Exception as e:
        if not silent:
            sublime.error_message("读取配置失败: {}".format(str(e)))
        return None


def sha256(file_path):
    h = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None

def run_winscp(script_lines, context_info=None):
    """
    执行 WinSCP 脚本，返回 stdout 和 stderr
    简洁输出，只显示文件名和进度
    """
    if not WINSCP_PATH or not os.path.exists(WINSCP_PATH):
        return "", "WinSCP 可执行文件不存在：{}".format(WINSCP_PATH)

    home_dir = os.path.expanduser("~")
    log_path = os.path.abspath(os.path.join(home_dir, "winscp.log"))

    # 控制日志文件大小，超过5MB则清空
    try:
        if os.path.exists(log_path) and os.path.getsize(log_path) > 5 * 1024 * 1024:  # 5MB
            with open(log_path, "w", encoding="utf-8") as f:
                f.write("")  # 清空文件
    except Exception as e:
        print("清理日志文件失败: {}".format(str(e)))

    # 临时脚本文件
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".tmp", mode="w", encoding="utf-8", newline='\n')
    tmp.write("\n".join(script_lines))
    tmp.close()
    script_path = tmp.name

    cmd = [
        WINSCP_PATH,
        "/script={}".format(script_path),
        "/log={}".format(log_path),
        "/ini=nul",
        "/console"
    ]

    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            creationflags=subprocess.CREATE_NO_WINDOW,
            bufsize=1
        )

        # 实时处理输出
        output_lines = []
        window = sublime.active_window()
        with open(log_path, "a", encoding="utf-8") as f:
            for raw_line in iter(process.stdout.readline, b""):
                try:
                    line = raw_line.decode("utf-8", errors="replace")
                except:
                    line = raw_line.decode("latin1", errors="replace")  # 兜底

                # 处理回车符
                line = line.replace('\r', '').replace('\x0d', '')

                f.write(line)
                output_lines.append(line)

                # 只显示进度信息
                if "%" in line and ("KB/s" in line or "MB/s" in line):
                    # 提取文件名和进度
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        progress = parts[0]
                        # 只显示文件名（最后一个部分可能是速度，所以取倒数第二个部分）
                        filename = parts[-2] if len(parts) > 2 else parts[1]

                        # 在输出面板中显示进度
                        if window:
                            show_output_panel(window, "{}: {}\n".format(filename, progress))

                        # 在状态栏显示进度
                        status_msg = "{}: {}".format(filename, progress)
                        sublime.set_timeout(lambda: sublime.status_message("FTG_SFTP: " + status_msg), 0)

        process.wait()

        out_bytes, err_bytes = process.communicate()
        try:
            out = out_bytes.decode("utf-8", errors="replace")
        except:
            out = out_bytes.decode("latin1", errors="replace")

        try:
            err = err_bytes.decode("utf-8", errors="replace")
        except:
            err = err_bytes.decode("latin1", errors="replace")

        return out, err

    except Exception as e:
        return "", "执行错误: {}".format(str(e))
    finally:
        try:
            if os.path.exists(script_path):
                os.remove(script_path)
        except:
            pass

def run_winscp_async(script_lines, on_finish=None, context_info=None):
    """异步执行，避免卡死 Sublime"""
    def task():
        # 在开始执行前显示输出面板
        window = sublime.active_window()
        if window and context_info:
            show_output_panel(window, "开始: {}\n".format(context_info))

        out, err = run_winscp(script_lines, context_info)
        if on_finish:
            try:
                on_finish(out, err)
            except Exception as e:
                error_msg = "[WinSCP][CallbackError] {}".format(str(e))
                print(error_msg)
                if window:
                    show_output_panel(window, error_msg + "\n")
    threading.Thread(target=task, daemon=True).start()

def normalize_path(path):
    """规范化路径，解决双盘符问题"""
    if not path:
        return ""

    # 移除多余引号
    path = path.strip().strip('"')

    # 如果已经是绝对路径，直接规范化
    if os.path.isabs(path):
        norm_path = os.path.normpath(path)
    else:
        norm_path = os.path.abspath(os.path.normpath(path))

    # 转换为 Windows 格式
    win_path = norm_path.replace("/", "\\")

    return win_path


def build_winscp_script(config, local_path, remote_path, action="put"):
    """构建 WinSCP 脚本命令"""
    # 获取配置参数
    host = config.get("host", "")
    port = config.get("port", "22")
    user = config.get("user", "")
    key_path = config.get("ssh_key_file", "")

    # 验证必要参数
    if not all([host, user, key_path]):
        return None, "缺少必要配置参数"

    # 规范化路径
    norm_key = normalize_path(key_path)
    norm_local = normalize_path(local_path)

    # 构建命令列表
    script_lines = [
        'option batch on',
        'option confirm off',
        'open sftp://{user}@{host}:{port}/ -privatekey="{key}" -hostkey="*"'.format(
            user=user, host=host, port=port, key=norm_key
        )
    ]

    if action == "put":
        script_lines.append('put "{}" "{}" -transfer=binary'.format(
            norm_local, remote_path
        ))
    else:
        script_lines.append('get "{}" "{}" -transfer=binary'.format(
            remote_path, norm_local
        ))


    script_lines.append('exit')

    return script_lines, None

def winscp_open_line(config):
    """统一生成 WinSCP open 连接行"""
    host = config.get("host", "")
    port = config.get("port", "22")
    user = config.get("user", "")
    key_path = normalize_path(config.get("ssh_key_file", ""))
    return 'open sftp://{user}@{host}:{port}/ -privatekey="{key}" -hostkey="*"'.format(
        user=user, host=host, port=port, key=key_path
    )


def build_recursive_download_script(config, local_dir, remote_dir, use_sha=False):
    """
    递归下载 remote_dir -> local_dir
    优先使用 WinSCP 的 synchronize（更快，是真正递归，支持增量）。
    - 增量：用 size（和时间）判断；SHA 可选（会很慢，只建议小量文件时开启）。
    """
    # 规范化
    lcd = normalize_path(local_dir)
    # WinSCP 的 path 用 /，让 remote_dir 全部 /
    rcd = remote_dir.replace("\\", "/").rstrip("/") or "/"

    lines = [
        "option batch on",
        "option confirm off",
        winscp_open_line(config),
        'lcd "{}"'.format(lcd),
        'cd "{}"'.format(rcd),
        # 同步远端 -> 本地；-criteria=size（含 mtime 参与传输判定）
        # -neweronly 让“仅远端较新/本地不存在”的文件下载，避免无谓覆盖
        # -preservetime 保留时间戳；-resume 续传；-transfer=binary 二进制传输
        'synchronize local "{}" "{}" -criteria=size -neweronly -preservetime -transfer=binary'.format(
            lcd, rcd
        ),
    ]

    # 可选：逐文件做 SHA 验证（注意：大量文件时会很慢）
    # 思路：让 WinSCP 计算远端 SHA，再与本地 sha256 比对；只打印，不强制重传。
    if use_sha:
        # 用 WinSCP 列出全部文件（递归），逐个 checksum
        # 注：WinSCP 没有直接给出全部文件列表的稳定文本接口，这里用 find -file 递归 + checksum
        lines += [
            # 递归列出普通文件
            'find . -file',
            # 下面的 echo 和 checksum 仅用于日志可读性，你可以按需删减
            # 在脚本级难以做复杂循环，这里让 WinSCP 输出 checksum，我们在日志里观察。
            # （若真要强 enforce，可换成 Python 控制逐文件 get + 校验，但速度会慢很多）
        ]

    lines.append("exit")
    return lines

# -------------------------------
# 输出面板工具函数
# -------------------------------
def show_output_panel(window, content):
    """
    线程安全的日志输出到 Sublime 面板，支持滚动显示
    """
    if not window:
        return

    def append():
        with output_lock:
            panel = window.create_output_panel("ftg_sftp")
            # 使用 append 命令追加内容，而不是替换
            panel.run_command("append", {"characters": content})
            # 滚动到面板底部
            panel.show(panel.size())
            window.run_command("show_panel", {"panel": "output.ftg_sftp"})

    sublime.set_timeout(append, 0)  # ✅ 在主线程里更新 UI

# -------------------------------
# 核心上传/下载函数
# -------------------------------
def sftp_sync(window, config, local_dir, remote_dir, upload=False, project_root=None):
    """
    local_dir: 要上传的目录
    remote_dir: 远端基准目录
    upload: 是否上传模式
    project_root: 项目根目录（用于路径映射）
    """
    ignore = config.get("ignore_regexes", [])
    tasks = []

    if not os.path.exists(local_dir):
        sublime.error_message("本地目录不存在: {}".format(local_dir))
        return

    for root_dir, dirs, files in os.walk(local_dir):
        # 过滤目录
        dirs[:] = [d for d in dirs if not any(re.match(p, d) for p in ignore)]
        for file in files:
            if any(re.match(p, file) for p in ignore):
                continue

            local_file = os.path.join(root_dir, file)
            if not os.path.exists(local_file):
                continue

            # ⭐ 路径映射逻辑修改
            if upload and project_root:
                # 按项目根算相对路径
                relative_path = os.path.relpath(local_file, project_root).replace("\\", "/")
            else:
                # 保持原逻辑
                relative_path = os.path.relpath(local_file, local_dir).replace("\\", "/")

            remote_file = os.path.join(remote_dir, relative_path).replace("\\", "/")

            tasks.append((local_file, remote_file))

    # ✅ 统一调全局 start_tasks（内部会根据 MULTI_THREAD 选择线程或直接执行）
    if tasks:
        start_tasks(window, config, tasks, upload)


def worker(window, config, tasks, upload=True):
    """
    执行批量上传/下载任务（带增量同步和 SHA256 校验）
    """
    total = len(tasks)
    batch_logs = []
    for idx, (local_file, remote_file) in enumerate(tasks, 1):
        skip_upload = False
        # -------------------------
        # 上传模式下做增量 & SHA 检查
        # -------------------------
        if upload and (INCREMENTAL_SYNC or SHA_CHECK):
            # 添加上下文信息
            context_info = os.path.dirname(remote_file) if upload else os.path.dirname(local_file)

            # 生成临时 WinSCP 脚本，检查远端文件
            check_script = [
                'option batch on',
                'option confirm off',
                'open sftp://{user}@{host}:{port}/ -privatekey="{key}" -hostkey="*"'.format(
                    user=config.get("user"),
                    host=config.get("host"),
                    port=config.get("port", 22),
                    key=normalize_path(config.get("ssh_key_file"))
                ),
                'stat "{}"'.format(remote_file),
            ]

            if SHA_CHECK:
                check_script.append('checksum sha256 "{}"'.format(remote_file))

            check_script.append('exit')

            out, _ = run_winscp(check_script, context_info)

            # 如果远端存在，才检查
            if "File size" in out or "Attributes" in out:
                if INCREMENTAL_SYNC:
                    local_mtime = int(os.path.getmtime(local_file))
                    m = re.search(r'Modified:\s+([0-9-]+\s+[0-9:]+)', out)
                    if m:
                        # 简单做：只比较时间戳（秒级）
                        remote_time_str = m.group(1)
                        try:
                            from datetime import datetime
                            remote_mtime = int(datetime.strptime(remote_time_str, "%Y-%m-%d %H:%M:%S").timestamp())
                            if local_mtime <= remote_mtime:
                                skip_upload = True
                        except:
                            pass

                if SHA_CHECK and not skip_upload:
                    local_sha = sha256(local_file)
                    m = re.search(r'sha256\s+([0-9a-fA-F]+)', out)
                    if m:
                        remote_sha = m.group(1)
                        if local_sha and remote_sha and local_sha.lower() == remote_sha.lower():
                            skip_upload = True

            if skip_upload:
                msg = "[{}/{}] 跳过(未修改): {}\n".format(idx, total, local_file)
                show_output_panel(window, msg)
                sublime.status_message("FTG_SFTP: 跳过 {}".format(os.path.basename(local_file)))
                continue

        # -------------------------
        # 正常上传/下载
        # -------------------------
        # 添加上下文信息（如果之前没有定义）
        if 'context_info' not in locals():
            context_info = os.path.dirname(remote_file) if upload else os.path.dirname(local_file)
            
        if upload:
            script, error = build_winscp_script(config, local_file, remote_file, "put")
        else:
            script, error = build_winscp_script(config, local_file, remote_file, "get")

        if error:
            show_output_panel(window, "错误: {}\n".format(error))
            continue

        # 使用修改后的 run_winscp_async 函数，它现在接受 context_info 参数
        def on_finish(out, err):
            msg = "\n[{}/{}] {}: {} -> {}\n{}\n{}\n".format(
                idx, total, 
                "UPLOAD" if upload else "DOWNLOAD",
                local_file, remote_file,
                out.strip(), err.strip()
            )
            batch_logs.append(msg)
            sublime.status_message("FTG_SFTP: {}/{} 文件完成".format(idx, total))
            show_output_panel(window, "\n".join(batch_logs))
            
        run_winscp_async(script, on_finish=on_finish, context_info=context_info)

# -------------------------------
# Sublime 命令
# -------------------------------
class FtgUploadCommand(sublime_plugin.WindowCommand):
    def is_visible(self, files=[], dirs=[]):
        return is_ftg_config_visible(self.window)

    def run(self, local_subdirs=[], files=[], dirs=[]):
        config_tuple = load_project_config(self.window)
        if not config_tuple:
            return
        config, root = config_tuple

        # ✅ 优先使用侧边栏传来的路径
        paths = files + dirs
        if not paths:
            # 没有传 → 按 local_subdirs 或项目根目录
            paths = [os.path.join(root, sd) for sd in (local_subdirs or ["."])]

        for path in paths:
            if os.path.isfile(path):
                # 上传单个文件
                rel_path = os.path.relpath(path, root).replace("\\", "/")
                remote_file = "{}/{}".format(config.get("remote_path", "/").rstrip("/"), rel_path)
                tasks = [(path, remote_file)]

                start_tasks(self.window, config, tasks, upload=True)

            elif os.path.isdir(path):
                # 上传整个目录
                sftp_sync(self.window, config, path, config.get("remote_path", "/"), upload=True)

class FtgDownloadCommand(sublime_plugin.WindowCommand):
    def is_visible(self, files=[], dirs=[]):
        return is_ftg_config_visible(self.window)

    def run(self, remote_subdirs=[], files=[], dirs=[], use_sha=False):
        config_tuple = load_project_config(self.window)
        if not config_tuple:
            return
        config, root = config_tuple

        # 显示输出面板
        show_output_panel(self.window, "开始下载...\n")

        # 情况 A：从 Side Bar 选择了"本地目录"
        if dirs:
            for local_dir in dirs:
                # 把远端 base 定位到 remote_path + 该目录相对于项目根的相对路径
                rel = os.path.relpath(local_dir, root).replace("\\", "/")
                if rel == ".":
                    remote_base = config.get("remote_path", "/").rstrip("/") or "/"
                else:
                    remote_base = "{}/{}".format(
                        (config.get("remote_path", "/").rstrip("/") or "/").rstrip("/"),
                        rel
                    ).replace("//", "/")

                # 用 synchronize local 做完整递归下载（增量）
                script = build_recursive_download_script(config, local_dir, remote_base, use_sha=SHA_CHECK and use_sha)

                def on_finish(out, err, remote_base=remote_base):
                    if err:
                        show_output_panel(self.window, "下载错误: {}\n".format(err))
                    else:
                        show_output_panel(self.window, "下载完成: {}\n".format(remote_base))

                run_winscp_async(script, on_finish=on_finish)

        # 情况 B：没有选择目录 → 按 remote_subdirs 或 remote_path
        else:
            remote_dirs = remote_subdirs or [config.get("remote_path", "/")]
            for rd in remote_dirs:
                local_dir = root  # 下载到项目根
                script = build_recursive_download_script(config, local_dir, rd, use_sha=SHA_CHECK and use_sha)

                def on_finish(out, err, rd=rd):
                    if err:
                        show_output_panel(self.window, "下载错误: {}\n".format(err))
                    else:
                        show_output_panel(self.window, "下载完成: {}\n".format(rd))

                run_winscp_async(script, on_finish=on_finish)

        # 集中输出日志
        sublime.status_message("FTG_SFTP: 下载开始")

class FtgAutoUploadOnSave(sublime_plugin.EventListener):
    def on_post_save_async(self, view):
        window = view.window()
        if not window:
            return

        # 静默模式加载配置（没有 config 就跳过，不提示）
        config_tuple = load_project_config(window, silent=True)
        if not config_tuple:
            return

        config, root = config_tuple
        if not config.get("upload_on_save", False):
            return

        file_path = view.file_name()
        if not file_path or not os.path.exists(file_path):
            return

        # 如果文件不在项目目录下，跳过
        if not file_path.startswith(root):
            return

        remote_root = config.get("remote_path", "/").rstrip("/")
        rel_path = os.path.relpath(file_path, root).replace("\\", "/")
        remote_file = "{}/{}".format(remote_root, rel_path)

        # 上传逻辑
        script, error = build_winscp_script(config, file_path, remote_file, "put")
        if error:
            show_output_panel(window, "错误: {}\n".format(error))
            return

        # 显示输出面板
        show_output_panel(window, "自动上传: {}\n".format(remote_file))

        def on_finish(out, err):
            if err:
                show_output_panel(window, "上传错误: {}\n".format(err))
            else:
                show_output_panel(window, "上传完成: {}\n".format(remote_file))
            sublime.status_message("FTG_SFTP: 上传完成 {}".format(os.path.basename(file_path)))

        run_winscp_async(script, on_finish=on_finish)

# ==============================
# 启动任务入口
# ==============================
def start_tasks(window, config, tasks, upload=True):
    if not tasks:
        show_output_panel(window, "[提示] 没有可执行的任务\n")
        return
    if MULTI_THREAD:
        threading.Thread(target=worker, args=(window, config, tasks, upload)).start()
    else:
        worker(window, config, tasks, upload)

# ==============================
# 默认配置模板
# ==============================
class FtgMapToRemoteCommand(sublime_plugin.WindowCommand):
    """
    通过交互方式快速生成 ftg-config.json
    仅在目录不存在 ftg-config.json 时显示菜单
    """
    def run(self, dirs=[]):
        if not dirs:
            sublime.error_message("请在 Side Bar 里选择一个目录")
            return

        # 用户选择的目录
        self.project_root = dirs[0]
        self.config_path = os.path.join(self.project_root, "ftg-config.json")

        if os.path.exists(self.config_path):
            sublime.message_dialog("已存在 ftg-config.json")
            return

        # 默认配置
        self.config = {
            "type": "sftp",
            "host": "",
            "user": "",
            "port": "22",
            "ssh_key_file": "",
            "remote_path": "/",
            "ignore_regexes": [
                "\\.sublime-(project|workspace)",
                "sftp-config(-alt\\d?)?\\.json",
                "sftp-settings\\.json",
                "/venv/",
                "\\.svn/",
                "\\.hg/",
                "\\.git/",
                "\\.bzr",
                "_darcs",
                "CVS",
                "\\.DS_Store",
                "Thumbs\\.db",
                "desktop\\.ini",
                "sftp-config",
                "\\.env",
                "/vendor/",
                "/addons",
                "/runtime/"
            ],
            "upload_on_save": True
        }

        # 交互输入
        self.window.show_input_panel("Host (服务器地址)", "", self.on_host, None, None)

    def on_host(self, value):
        self.config["host"] = value.strip()
        self.window.show_input_panel("User (用户名)", "root", self.on_user, None, None)

    def on_user(self, value):
        self.config["user"] = value.strip()
        self.window.show_input_panel("Port (默认22)", "22", self.on_port, None, None)

    def on_port(self, value):
        self.config["port"] = value.strip() or "22"
        self.window.show_input_panel("Remote Path (远程目录)", "/", self.on_remote_path, None, None)

    def on_remote_path(self, value):
        self.config["remote_path"] = value.strip() or "/"
        self.window.show_input_panel("SSH Key File (本地私钥路径)", "C:/Users/You/.ssh/id_rsa.ppk", self.on_key_file, None, None)

    def on_key_file(self, value):
        self.config["ssh_key_file"] = value.strip()
        self.save_config()

    def save_config(self):
        try:
            with open(self.config_path, "w", encoding="utf-8") as f:
                json.dump(self.config, f, indent=4, ensure_ascii=False)
            sublime.message_dialog("ftg-config.json 已创建:\n{}".format(self.config_path))
        except Exception as e:
            sublime.error_message("保存配置失败: {}".format(str(e)))

    def is_visible(self, dirs):
        """只有目录下不存在 ftg-config.json 时才显示菜单"""
        if not dirs:
            return False
        folder = dirs[0]
        config_path = os.path.join(folder, "ftg-config.json")
        return not os.path.exists(config_path)

def is_ftg_config_visible(window):
    """检查是否存在 ftg-config.json"""
    project_folders = window.folders()
    if not project_folders:
        return False
    root = project_folders[0]
    config_path = os.path.join(root, "ftg-config.json")
    return os.path.exists(config_path)




