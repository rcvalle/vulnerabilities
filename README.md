Vulnerabilities
===============


* [CVE-2013-2143](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2013-2143)  
  The users controller in Katello 1.5.0-14 and earlier, and Red Hat Satellite, does not check authorization for the update_roles action, which allows remote authenticated users to gain privileges by setting a user account to an administrator account.

* [CVE-2013-2121](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2013-2121)  
  Eval injection vulnerability in the create method in the Bookmarks controller in Foreman before 1.2.0-RC2 allows remote authenticated users with permissions to create bookmarks to execute arbitrary code via a controller name attribute.

* [CVE-2013-2113](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2013-2113)  
  The create method in app/controllers/users_controller.rb in Foreman before 1.2.0-RC2 allows remote authenticated users with permissions to create or edit other users to gain privileges by (1) changing the admin flag or (2) assigning an arbitrary role.

* [CVE-2013-2068](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2013-2068)  
  Multiple directory traversal vulnerabilities in the AgentController in Red Hat CloudForms Management Engine 2.0 allow remote attackers to create and overwrite arbitrary files via a .. (dot dot) in the filename parameter to the (1) log, (2) upload, or (3) linuxpkgs method.

* [CVE-2013-2050](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2013-2050)  
  SQL injection vulnerability in the miq_policy controller in Red Hat CloudForms 2.0 Management Engine (CFME) 5.1 and ManageIQ Enterprise Virtualization Manager 5.0 and earlier allows remote authenticated users to execute arbitrary SQL commands via the profile[] parameter in an explorer action.

* [CVE-2013-2049](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2013-2049)  
  Red Hat CloudForms 2 Management Engine (CFME) allows remote attackers to conduct session tampering attacks by leveraging use of a static secret_token.rb secret.

* [CVE-2012-0815](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-0815)  
  The headerVerifyInfo function in lib/header.c in RPM before 4.9.1.3 allows remote attackers to cause a denial of service (crash) and possibly execute arbitrary code via a negative value in a region offset of a package header, which is not properly handled in a numeric range comparison.

* [CVE-2012-0061](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-0061)  
  The headerLoad function in lib/header.c in RPM before 4.9.1.3 does not properly validate region tags, which allows user-assisted remote attackers to cause a denial of service (crash) and possibly execute arbitrary code via a large region size in a package header.

* [CVE-2012-0060](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-0060)  
  RPM before 4.9.1.3 does not properly validate region tags, which allows remote attackers to cause a denial of service (crash) and possibly execute arbitrary code via an invalid region tag in a package header to the (1) headerLoad, (2) rpmReadSignature, or (3) headerVerify function.

* [CVE-2010-0415](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2010-0415)  
  The do_pages_move function in mm/migrate.c in the Linux kernel before 2.6.33-rc7 does not validate node values, which allows local users to read arbitrary kernel memory locations, cause a denial of service (OOPS), and possibly have unspecified other impact by specifying a node that is not part of the kernel's node set.

* [CVE-2009-2727](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-2727)  
  Stack-based buffer overflow in the _tt_internal_realpath function in the ToolTalk library (libtt.a) in IBM AIX 5.2.0, 5.3.0, 5.3.7 through 5.3.10, and 6.1.0 through 6.1.3, when the rpc.ttdbserver daemon is enabled in /etc/inetd.conf, allows remote attackers to execute arbitrary code via a long XDR-encoded ASCII string to remote procedure 15.

* [CVE-2009-2407](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-2407)  
  Heap-based buffer overflow in the parse_tag_3_packet function in fs/ecryptfs/keystore.c in the eCryptfs subsystem in the Linux kernel before 2.6.30.4 allows local users to cause a denial of service (system crash) or possibly gain privileges via vectors involving a crafted eCryptfs file, related to a large encrypted key size in a Tag 3 packet.

* [CVE-2009-2406](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-2406)  
  Stack-based buffer overflow in the parse_tag_11_packet function in fs/ecryptfs/keystore.c in the eCryptfs subsystem in the Linux kernel before 2.6.30.4 allows local users to cause a denial of service (system crash) or possibly gain privileges via vectors involving a crafted eCryptfs file, related to not ensuring that the key signature length in a Tag 11 packet is compatible with the key signature buffer size.

* [CVE-2007-5246](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-5246)  
  Multiple stack-based buffer overflows in Firebird LI 2.0.0.12748 and 2.0.1.12855, and WI 2.0.0.12748 and 2.0.1.12855, allow remote attackers to execute arbitrary code via (1) a long attach request on TCP port 3050 to the isc_attach_database function or (2) a long create request on TCP port 3050 to the isc_create_database function.

* [CVE-2007-5245](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-5245)  
  Multiple stack-based buffer overflows in Firebird LI 1.5.3.4870 and 1.5.4.4910, and WI 1.5.3.4870 and 1.5.4.4910, allow remote attackers to execute arbitrary code via (1) a long service attach request on TCP port 3050 to the SVC_attach function or (2) unspecified vectors involving the INET_connect function.

* [CVE-2007-5244](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-5244)  
  Stack-based buffer overflow in Borland InterBase LI 8.0.0.53 through 8.1.0.253 on Linux, and possibly unspecified versions on Solaris, allows remote attackers to execute arbitrary code via a long attach request on TCP port 3050 to the open_marker_file function.

* [CVE-2007-5243](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-5243)  
  Multiple stack-based buffer overflows in Borland InterBase LI 8.0.0.53 through 8.1.0.253, and WI 5.1.1.680 through 8.1.0.257, allow remote attackers to execute arbitrary code via (1) a long service attach request on TCP port 3050 to the (a) SVC_attach or (b) INET_connect function, (2) a long create request on TCP port 3050 to the (c) isc_create_database or (d) jrd8_create_database function, (3) a long attach request on TCP port 3050 to the (e) isc_attach_database or (f) PWD_db_aliased function, or unspecified vectors involving the (4) jrd8_attach_database or (5) expand_filename2 function.

* [CVE-2007-4684](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-4684)  
  Integer overflow in the kernel in Apple Mac OS X 10.4 through 10.4.10 allows local users to execute arbitrary code via a large num_sels argument to the i386_set_ldt system call.


[^1]: Descriptions from [MITRE CVE List](https://www.cve.org/).
