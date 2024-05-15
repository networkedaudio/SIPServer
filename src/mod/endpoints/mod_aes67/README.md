## Building GStreamer for Windows
### Using Cerbero

Cerbero is a cross-platform build aggregator for Open Source projects that builds
and creates native packages for different platforms, architectures and distributions.
It supports both native compilation and cross compilation and can run on macOS,
Linux, and Windows. (refer https://gitlab.freedesktop.org/gstreamer/cerbero/-/blob/main/README.md?ref_type=heads for more information)

Note: The build instructions may slightly vary based on the version of the GStreamer we want to build. This page uses V1.24.3 as an example taken from https://gitlab.freedesktop.org/gstreamer/cerbero/-/blob/1.24.3/README.md?ref_type=tags. Please refer the corresponding README.md for build instructions of a particular GStreamer version


1. Open a PowerShell window (preferably as an administrator)
2. Pull the latest cerbero code

    `$ git clone https://gitlab.freedesktop.org/gstreamer/cerbero.git`

3. Checkout the version that matches the desired version of the GStreamer release from the tags (https://gitlab.freedesktop.org/gstreamer/cerbero/-/tags)

    `$ git checkout 1.24.3`
4. Enter the cerbero directory

    `$ cd cebero`

5. Enable running scripts

    `$ Set-ExecutionPolicy -ExecutionPolicy Unrestricted`

6. Run the script to install tools. It will auto-detect and
installs the below necessary tools with [Chocolatey](https://chocolatey.org/)
    - Visual Studio 2019 or 2022 Build Tools
    - CMake
    - MSYS2
    - Git
    - Python 3
    - WiX

    `$ .\tools\bootstrap-windows.ps1`

7. Create a local configuration file to pick non-default branches which contain our custom unmerged patches on top of the release/upstream (1.24.3) version we are building. Add the below contents into a file, let's name it `localconf.cbc`

    ```
    # Set custom remote and branch for all gstreamer recipes
    recipes_remotes = {'gst-plugins-rs': {'rs-remote': 'git@github.com:networkedaudio/gst-plugins-rs.git'}, 'gstreamer-1.0': {'gst-remote': 'git@github.com:networkedaudio/GStreamer.git'}}
    recipes_commits = {'gst-plugins-rs': 'rs-remote/cerbero-custom-rs-1.24.3', 'gstreamer-1.0': 'gst-remote/cerbero-custom'}

    # Use VS2019
    vs_install_version = 'vs16'
    ```
    Note:
    If the repo url scheme is SSH (like in the above example) and not HTTPS it needs to verification and authentication while fetching the code. So create an ssh private key for the build machine and add that to your [GitHub account](https://docs.github.com/en/enterprise-cloud@latest/authentication/connecting-to-github-with-ssh/adding-a-new-ssh-key-to-your-github-account).
    Since the cerbero build runs in msys2 shell the SSH keys present in the default user path in Windows will not be picked. So add the `known_hosts` file and public/private key files to the msys2 home directory for e.g. C:\msys2\home\<username>\.ssh

8. Run the cerbero bootstrap. It will install all the missing parts of the build system and necessary toolchains

    `$ ./cerbero-uninstalled -c localconf.cbc -c config/win64.cbc -v visualstudio bootstrap`

9. Build. This will fetch and build gstreamer plugins with all necessary dependant libraries

    `$ ./cerbero-uninstalled -c localconf.cbc -c config/win64.cbc -v visualstudio package gstreamer-1.0`

10. If the build is successful, we should have the two installer (.msi) files created in the cerbero directory. Run them both to install GStreamer