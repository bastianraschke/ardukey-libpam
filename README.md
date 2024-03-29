# PAM ArduKey

## Installation

First you have to install the server via your package manager. For example:

    ~# apt-get install libpam-ardukey

Important note: First you need to add the "PM Codeworks" repository. See [this page](http://www.pm-codeworks.de/repository.html) for the instructions.

## Manual package build and installation

If you don't want to use pre-build packages, you can easyly build your own packages using the tool `debuild`:

    ~$ cd ./src/
    ~$ debuild

After that, the generated packages can be found in the upper directory. You can install the packages with `dpkg`:

    ~# dpkg -i ../*.deb

And fix the dependency problems, if occurred:

    ~# apt-get -f install

## Configuration

Note: All changes will be done in file `/etc/pam-ardukey.conf`.

First we have to change the auth server list:

    servers = 127.0.0.1:8080,127.0.0.2:8080

In this case the PAM module will connect the servers which are listening on the addresses `127.0.0.1` and `127.0.0.2` (both on port 8080). If the first server in the list is not available, the next server will be tried to connect.

**Important note:** You never should provide the auth-server on the same machine as the PAM module (it doesn't add any security). So change the value to the address(es) of your auth-server(s). For example:

    servers = 11.22.33.44:8080,11.22.33.45:8080

Now we need to change the "API key" to provide signed communication between the PAM module and the auth-server. The API key (consisting of an API id and a shared secret) must be generated on the auth-server machine. For example:

    api_id = 1
    shared_secret = 4NJCNJEQJCAZW58EQKQRO8MI6DDHDRI9HLF2J7LFA8WF5K7HCN1DD9YN1WRJLREU

## Setup SSH daemon for two factor authentication (2FA)

**Important:** You need a OpenSSH server > 6.2 for two factor feature.

First check if the parameter `ChallengeResponseAuthentication` is set to `yes` in the SSH server configuration `/etc/ssh/sshd_config`.

Add the following block to the SSH server configuration `/etc/ssh/sshd_config`:

    Match Group twofactor
        AuthenticationMethods publickey,keyboard-interactive

Now we need to create the above user group:

    ~# addgroup twofactor

Create the PAM profile with following command:

    ~# echo "auth sufficient pam_python.so pam_ardukey.py" > /etc/pam.d/ardukey-twofactor

Add the following block to `/etc/pam.d/sshd` (above `@include common-auth`):

    # ArduKey two factor authentication:
    @include ardukey-twofactor

And restart the SSH server:

    ~# /etc/init.d/ssh restart

## Setup a user for SSH with 2FA

In this example the user `root` will be protected by 2FA.

Just use the following command to add the user `root` (the public ID of his ArduKey device must be entered). This means this ArduKey device will be assigned to the user - be sure this is the correct public ID!

    ~# pam-ardukey-conf --add-user root
    Are you sure you want to assign an ArduKey device to the user "root"? (Y/n) Y
    Please enter the public ID of your ArduKey device: cccccccccccb
    Successfully assigned the ArduKey device to the user "root"!

Finally add the user `root` to the `twofactor` group:

    ~# adduser root twofactor

From now, the SSH login requires additional 2FA with ArduKey.

## Further information

Additionally you can check out [this article](https://sicherheitskritisch.de/2015/06/ardukey-otp-generator-fuer-zweifaktor-authentifizierung-2fa-mit-arduino/), which explains the complete ArduKey infrastructure in detail (the article is in German).

## Questions

If you have any questions to this project, just ask me via email:

<bastian.raschke@posteo.de>
