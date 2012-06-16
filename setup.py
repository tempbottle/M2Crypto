#!/usr/bin/env python

"""
Distutils/setuptools installer for M2Crypto.

Copyright (c) 1999-2004, Ng Pheng Siong. All rights reserved.

Portions created by Open Source Applications Foundation (OSAF) are
Copyright (C) 2004-2007 OSAF. All Rights Reserved.

Copyright 2008-2009 Heikki Toivonen. All rights reserved.
"""

import os, sys
try:
    from setuptools import setup
    from setuptools.command import build_ext
except ImportError:
    from distutils.core import setup
    from distutils.command import build_ext

from distutils.core import Extension


class _M2CryptoBuildExt(build_ext.build_ext):
    '''Specialization of build_ext to enable swig_opts to inherit any 
    include_dirs settings made at the command line or in a setup.cfg file'''
    user_options = build_ext.build_ext.user_options + \
            [('openssl=', 'o', 'Prefix for openssl installation location')]

    def initialize_options(self):
        '''Overload to enable custom openssl settings to be picked up'''

        build_ext.build_ext.initialize_options(self)
        
        # openssl is the attribute corresponding to openssl directory prefix
        # command line option
        if os.name == 'nt':
            self.libraries = ['ssleay32', 'libeay32']
            self.openssl = 'c:\\pkg'
        else:
            self.libraries = ['ssl', 'crypto']
            self.openssl = '/usr'
       
    
    def finalize_options(self):
        '''Overloaded build_ext implementation to append custom openssl
        include file and library linking options'''

        build_ext.build_ext.finalize_options(self)

        opensslIncludeDir = os.path.join(self.openssl, 'include')
        opensslLibraryDir = os.path.join(self.openssl, 'lib')
        
        self.swig_opts = ['-I%s' % i for i in self.include_dirs + \
                          [opensslIncludeDir]]
        self.swig_opts.append('-includeall')
        #self.swig_opts.append('-D__i386__') # Uncomment for early OpenSSL 0.9.7 versions, or on Fedora Core if build fails
        #self.swig_opts.append('-DOPENSSL_NO_EC') # Try uncommenting if you can't build with EC disabled
        
        self.include_dirs += [os.path.join(self.openssl, opensslIncludeDir),
                              os.path.join(os.getcwd(), 'SWIG')]        
            
        if sys.platform == 'cygwin':
            # Cygwin SHOULD work (there's code in distutils), but
            # if one first starts a Windows command prompt, then bash,
            # the distutils code does not seem to work. If you start
            # Cygwin directly, then it would work even without this change.
            # Someday distutils will be fixed and this won't be needed.
            self.library_dirs += [os.path.join(self.openssl, 'bin')]
               
        self.library_dirs += [os.path.join(self.openssl, opensslLibraryDir)]


if sys.version_info < (2,4):

    # This copy of swig_sources is from Python 2.2.

    def swig_sources (self, sources):

        """Walk the list of source files in 'sources', looking for SWIG
        interface (.i) files.  Run SWIG on all that are found, and
        return a modified 'sources' list with SWIG source files replaced
        by the generated C (or C++) files.
        """

        new_sources = []
        swig_sources = []
        swig_targets = {}

        # XXX this drops generated C/C++ files into the source tree, which
        # is fine for developers who want to distribute the generated
        # source -- but there should be an option to put SWIG output in
        # the temp dir.

        if self.swig_cpp:
            target_ext = '.cpp'
        else:
            target_ext = '.c'

        for source in sources:
            (base, ext) = os.path.splitext(source)
            if ext == ".i":             # SWIG interface file
                new_sources.append(base + target_ext)
                swig_sources.append(source)
                swig_targets[source] = new_sources[-1]
            else:
                new_sources.append(source)

        if not swig_sources:
            return new_sources

        swig = self.find_swig()
        swig_cmd = [swig, "-python", "-ISWIG"]
        if self.swig_cpp:
            swig_cmd.append("-c++")

        swig_cmd += self.swig_opts 

        for source in swig_sources:
            target = swig_targets[source]
            self.announce("swigging %s to %s" % (source, target))
            self.spawn(swig_cmd + ["-o", target, source])

        return new_sources
    
    build_ext.build_ext.swig_sources = swig_sources


m2crypto = Extension(name = 'M2Crypto.__m2crypto',
                     sources = ['SWIG/_m2crypto.i'],
                     extra_compile_args = ['-DTHREADING'],
                     #extra_link_args = ['-Wl,-search_paths_first'], # Uncomment to build Universal Mac binaries
                     )

setup(name = 'M2Crypto',
      version = '0.22',
      description = 'M2Crypto: A Python crypto and SSL toolkit',
      long_description = '''\
M2Crypto is the most complete Python wrapper for OpenSSL featuring RSA, DSA,
DH, EC, HMACs, message digests, symmetric ciphers (including AES); SSL
functionality to implement clients and servers; HTTPS extensions to Python's
httplib, urllib, and xmlrpclib; unforgeable HMAC'ing AuthCookies for web
session management; FTP/TLS client and server; S/MIME; ZServerSSL: A HTTPS
server for Zope and ZSmime: An S/MIME messenger for Zope. M2Crypto can also be
used to provide SSL for Twisted. Smartcards supported through the Engine
interface.''',
      license = 'BSD-style license',
      platforms = ['any'],
      author = 'Ng Pheng Siong',
      author_email = 'ngps at sandbox rulemaker net',
      maintainer = 'Heikki Toivonen',
      maintainer_email = 'heikki@osafoundation.org',
      url = 'http://chandlerproject.org/Projects/MeTooCrypto',
      packages = ['M2Crypto', 'M2Crypto.SSL', 'M2Crypto.PGP'],
      classifiers = [
          'Development Status :: 5 - Production/Stable',
          'Intended Audience :: Developers',
          'Operating System :: OS Independent',
          'Programming Language :: C',
          'Programming Language :: Python',
          'Topic :: Security :: Cryptography',
          'Topic :: Software Development :: Libraries :: Python Modules',
      ],

      ext_modules = [m2crypto],
      test_suite='tests.alltests.suite',
      cmdclass = {'build_ext': _M2CryptoBuildExt}
      )
