# Overview

This is the code relating to a project to simplify the act of creating a CA, signing a binary with the CA and then installing the CA on the target machine. It investigates the extent to which this can be achieved without the benefit of a GUI and shows how this can be modified to generate valid EV certificates which are trusted by Windows. It is intended for penetration testers who are looking to install an implant binary which looks as legitimate as possible. None of these techniques are new, but it is hoped that this tool and project will make them easier and more accessible.

# Details

A detailed description of the research, including tool usage instructions, is available at https://labs.mwrinfosecurity.com/blog/. It is designed to explain how to:

* Create an "Authenticode" EXE digital signing certificate.
* Cover a variety of methods of installing this on a target's machine, either as a user or local administrator.
* A demonstration and an example of the insertion of an Extended Validation (EV) certificate which is honoured by Windows and IE.
* A discussion of why the name of both the signer and the EXE metadata can be important in later versions of Windows.
