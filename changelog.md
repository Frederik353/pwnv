

# changelog

- Default is now to wait for challenges (polls every 10s)
- Added --no-wait / -n to skip waiting
- Kept --interval / -i (default: 10s)

#### Default: wait for challenges, poll every 10s
```sh
pwnv ctf add my-ctf
```

#### Custom interval
```sh
pwnv ctf add my-ctf --interval 30
```

#### Don't wait if no challenges
```sh
pwnv ctf add my-ctf --no-wait
```

