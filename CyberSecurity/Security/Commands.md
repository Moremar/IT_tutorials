# Useful Linux commands

## Permissions

```commandline
sudo ls                       // run ls with root permission
sudo -l                       // show what the current user can do in sudo
sudo -l -U <USERNAME>         // show what a specific user can do in sudo
sudo su                       // switch to the root user
su <USERNAME>                 // switch to a specific user (require password)
sudo deluser <USERNAME> sudo  // delete a user from the sudo group
```

## Processes

```commandline
top                              // dynamic list of running processes
kill <PID>                       // stops a running process
crontab -l                       // list scheduled processes
```

## Services

```commandline
// Restart a service with systemctl
sudo systemctl restart ssh       // restart SSH after a config change in /etc/ssh/sshd_config
sudo systemctl restart jenkins   // restart Jenkins after a config change in /var/lib/jenkins/

systemctl list-unit-files        // list all running services
systemctl status <SERVICE_NAME>  // see info about a service
systemctl stop <SERVICE_NAME>    // stop a running service
systemctl disable <SERVICE_NAME>  // disable a service
systemctl daemon-reload           // reload all service configurations (and remove remnants of old services)
```