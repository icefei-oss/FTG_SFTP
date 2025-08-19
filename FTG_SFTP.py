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

def run_winscp(script_lines):
    """
    执行 WinSCP 脚本，返回 stdout 和 stderr
    """
    if not WINSCP_PATH or not os.path.exists(WINSCP_PATH):
        return "", "WinSCP 可执行文件不存在：{}".format(WINSCP_PATH)

    home_dir = os.path.expanduser("~")
    log_path = os.path.abspath(os.path.join(home_dir, "winscp.log"))

    # 临时脚本文件（唯一，避免覆盖）
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".tmp", mode="w", encoding="utf-8")
    tmp.write("\n".join(script_lines))
    tmp.close()
    script_path = tmp.name

    # 调试输出（开发用）
    print("DEBUG WinSCP script ==================")
    print("script path =", script_path)
    print("log path =", log_path)
    print("======================================")

    cmd = [
        WINSCP_PATH,
        "/script={}".format(script_path),
        "/log={}".format(log_path),
        "/ini=nul"  # 避免弹出 GUI 窗口
    ]

    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            creationflags=subprocess.CREATE_NO_WINDOW  # ✅ 阻止黑窗口一闪一闪
        )
        out_bytes, err_bytes = process.communicate()

        out = out_bytes.decode("utf-8", errors="replace")
        err = err_bytes.decode("utf-8", errors="replace")

        return out, err
    except Exception as e:
        return "", "执行错误: {}".format(str(e))
    finally:
        try:
            if os.path.exists(script_path):
                os.remove(script_path)
        except:
            pass

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

# -------------------------------
# 输出面板工具函数
# -------------------------------
def show_output_panel(window, content):
    """
    线程安全的日志输出到 Sublime 面板
    """
    if not window:
        return

    def append():
        with output_lock:
            panel = window.create_output_panel("ftg_sftp")
            panel.run_command("append", {"characters": content})
            window.run_command("show_panel", {"panel": "output.ftg_sftp"})

    sublime.set_timeout(append, 0)  # ✅ 在主线程里更新 UI

# -------------------------------
# 核心上传/下载函数
# -------------------------------
def sftp_sync(window, config, local_dir, remote_dir, upload=False):
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
    for idx, (local_file, remote_file) in enumerate(tasks, 1):
        skip_upload = False
        # -------------------------
        # 上传模式下做增量 & SHA 检查
        # -------------------------
        if upload and (INCREMENTAL_SYNC or SHA_CHECK):

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

            out, _ = run_winscp(check_script)

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
        if upload:
            script, error = build_winscp_script(config, local_file, remote_file, "put")
        else:
            script, error = build_winscp_script(config, local_file, remote_file, "get")

        if error:
            show_output_panel(window, "错误: {}\n".format(error))
            continue

        out, err = run_winscp(script)
        msg = "[{}/{}] {}: {} -> {}\n{}\n{}\n".format(
            idx, total,
            "上传" if upload else "下载",
            local_file, remote_file,
            out.strip(), err.strip()
        )
        show_output_panel(window, msg)
        sublime.status_message("FTG_SFTP: {}/{} 文件完成".format(idx, total))

# -------------------------------
# Sublime 命令
# -------------------------------
class FtgUploadCommand(sublime_plugin.WindowCommand):
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
    def run(self, remote_subdirs=[], files=[], dirs=[]):
        config_tuple = load_project_config(self.window)
        if not config_tuple:
            return
        config, root = config_tuple

        # ✅ 优先使用侧边栏传来的路径
        paths = files + dirs
        if not paths:
            # 没有传 → 按 remote_subdirs 或整个 remote_path
            remote_dirs = remote_subdirs or [config.get("remote_path", "/")]
            for rd in remote_dirs:
                sftp_sync(self.window, config, root, rd, upload=False)
            return

        for path in paths:
            if os.path.isfile(path):
                # 下载单个文件
                rel_path = os.path.relpath(path, root).replace("\\", "/")
                remote_file = "{}/{}".format(config.get("remote_path", "/").rstrip("/"), rel_path)
                tasks = [(path, remote_file)]

                start_tasks(self.window, config, tasks, upload=False)

            elif os.path.isdir(path):
                # 下载整个目录
                sftp_sync(self.window, config, path, config.get("remote_path", "/"), upload=False)

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

        out, err = run_winscp(script)
        show_output_panel(window, "[上传单文件] {} -> {}\n{}\n{}\n".format(file_path, remote_file, out, err))
        sublime.status_message("FTG_SFTP: 上传完成 {}".format(os.path.basename(file_path)))

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

