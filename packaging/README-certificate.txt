DROIDBOARD - CERTIFICATE INSTALLATION
=====================================

This package contains a self-signed public certificate. It does not contain the
private key used to sign Droidboard.

Before installing the certificate, compare the displayed thumbprint with the
value supplied by the publisher through a separate, trusted channel.

Instructions:

1. Double-click Install-Certificate.cmd.
2. Check the displayed subject, expiration date, and thumbprint.
3. Type INSTALL only if the details are correct.
4. Run Droidboard-Setup-windows-x64.exe.

The script installs the certificate into the Root and TrustedPublisher stores for
the current user only. Administrator privileges are not required. Windows will
then trust applications signed with this key for that user.

This configuration is suitable for internal or controlled distribution. It does
not create public Microsoft SmartScreen reputation and is not equivalent to a
certificate issued by a publicly trusted Certification Authority.
