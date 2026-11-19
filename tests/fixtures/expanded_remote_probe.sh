set -eu

for tool in Xvfb xvfb-run xfreerdp xdotool xclip scrot vncviewer x11vnc tesseract; do
  command -v "$tool" | sed "s/^/found: /"
done

Xvfb :99 -screen 0 1024x768x24 -nolisten tcp >/tmp/xvfb.log 2>&1 &
xvfb_pid=$!
trap 'kill "$xvfb_pid" 2>/dev/null || true' EXIT
sleep 1

DISPLAY=:99 xdpyinfo | head -n 8
DISPLAY=:99 scrot /tmp/remote-probe.png
identify /tmp/remote-probe.png
tesseract --list-langs
DISPLAY=:99 xfreerdp /version
