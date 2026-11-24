# Authorized use only

This repository contains working exploit code for CVE-2026-114938. It
deliberately corrupts a JVM heap and executes shellcode.

It is provided for **education, vulnerability research, and detection
engineering** only.

**Do not use it against any system you do not own or do not have explicit
written permission to test.** Unauthorized access to computer systems is
illegal in most jurisdictions and may result in criminal or civil liability.

The code is designed to run inside the disposable Docker container this
repository builds. Running the `codecache` stage outside that container
overwrites executable memory in the target JVM and will terminate it.

The authors accept no liability for misuse or for any damage caused by running
this software.

Licensed under the MIT License; see [LICENSE](LICENSE).
