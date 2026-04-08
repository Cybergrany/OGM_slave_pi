ensure these in /boot/firmware/config.txt

```bash
dtparam=audio=on
audio_pwm_mode=2

```

install audo utils:

```bash
sudo apt update
sudo apt install pulseaudio-utils pipewire pipewire-pulse pipewire-audio pavucontrol
```

run ```pactl list sinks short```

example output: 
```
56      alsa_output.platform-3f00b840.mailbox.stereo-fallback   PipeWire       s16le 2ch 48000Hz        SUSPENDED
```

set the pipe:
```
pactl set-default-sink alsa_output.platform-3f00b840.mailbox.stereo-fallback
```

Then full volume:
```
pactl set-sink-volume @DEFAULT_SINK@ 100%
```



