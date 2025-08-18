👌 我帮你整理和更新一下 README.md，让它和 **FTG\_SFTP 当前已实现的功能**完全对齐，不写“未来/预留”还没实现的部分，保证用户不会误解。

---

# FTG\_SFTP

基于 **WinSCP** 的 Sublime Text SFTP 插件。
支持 **一键上传/下载** 文件或文件夹，支持 **保存时自动上传**，并在 **侧边栏和编辑区右键菜单** 中提供集成操作。

---

## ✨ 功能特性

* 📂 **侧边栏右键菜单**

  * `FTG SFTP > Upload File` 上传单个文件
  * `FTG SFTP > Upload Folder` 上传整个文件夹
  * `FTG SFTP > Download File` 下载单个文件
  * `FTG SFTP > Download Folder` 下载整个文件夹

* 📝 **编辑区右键菜单**

  * 对当前正在编辑的文件执行上传/下载

* 💾 **自动上传**

  * 可选：保存文件时自动上传到远程服务器

* ⚡ **批量任务支持**

  * 自动递归遍历目录
  * 忽略文件规则（正则表达式）

* 🔒 **安全连接**

  * 基于 SSH 私钥认证
  * 避免密码明文

* 📋 **日志面板**

  * 在 Sublime 的 **输出面板** 中查看详细日志
  * 调用 WinSCP 时隐藏黑窗口

---

## 📦 安装

1. 确保已安装 **[WinSCP](https://winscp.net/eng/download.php)**，并找到 `WinSCP.com` 的路径。

   > 注意：必须使用 `WinSCP.com`，而不是 `WinSCP.exe`。

2. 将插件目录放到：

   ```
   Packages/FTG_SFTP
   ```

3. 在 `Packages/User/FTG_SFTP.sublime-settings` 中配置参数。

---

## ⚙️ 配置

### 1. 插件配置（全局）

`Packages/User/FTG_SFTP.sublime-settings`

```json
{
    "winscp_path": "D:/software/WinSCP/WinSCP.com",
    "multi_thread": true,
    "upload_on_save": false
}
```

### 2. 项目配置（针对每个项目）

在项目根目录下新建 **ftg-config.json**：

```json
{
    "host": "example.com",
    "port": 22,
    "user": "deploy",
    "ssh_key_file": "C:/Users/you/.ssh/id_rsa.ppk",
    "remote_path": "/var/www/project",
    "ignore_regexes": [
        "\\.git",
        "\\.DS_Store",
        "node_modules"
    ],
    "upload_on_save": true
}
```

---

## 🚀 使用方法

### 1. 侧边栏菜单

* 在文件上右键 → **FTG SFTP > Upload File**
* 在文件夹上右键 → **FTG SFTP > Upload Folder**
* 在文件上右键 → **FTG SFTP > Download File**
* 在文件夹上右键 → **FTG SFTP > Download Folder**

### 2. 编辑区菜单

* 在编辑区右键 → **FTG SFTP > Upload File**
* 在编辑区右键 → **FTG SFTP > Download File**

### 3. 命令面板

* `Ctrl+Shift+P` → 输入 `FTG` → 选择 `FTG Upload` 或 `FTG Download`

### 4. 自动上传

* 在全局或项目配置里开启 `"upload_on_save": true`
* 保存文件时自动上传到远程服务器

---

## 📑 日志查看

插件运行时会在 **输出面板** 中显示详细日志：

```
[1/3] 上传: local/file.js -> /var/www/project/file.js
[2/3] 上传: local/style.css -> /var/www/project/style.css
...
```

菜单路径：
**View > Show Console → 选择 FTG SFTP**

---

## ⚠️ 注意事项

* 仅支持 **Windows + WinSCP** 环境
* 必须使用 **WinSCP.com** 而不是 WinSCP.exe
* **项目根目录必须包含 ftg-config.json** 才会启用插件功能
* **当前打开的文件如果不在项目目录内，不会自动上传**

---

这样写，完全匹配你现在插件的功能，没有写“增量同步 / SHA 校验”等未来功能。

要不要我帮你写一个 **README 国际版（英文版）**，方便以后发布到 Package Control？
