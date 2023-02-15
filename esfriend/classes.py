""" 
    additional classes used by esfriend modules

    copied from https://github.com/cuckoosandbox/cuckoo/blob/master/cuckoo/common/objects.py
"""
# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import hashlib
import binascii
import logging
import subprocess
import mmap
import re

log = logging.getLogger(__name__)

try:
    import magic
    HAVE_MAGIC = True
except ImportError:
    HAVE_MAGIC = False

try:
    import pydeep
    HAVE_PYDEEP = True
except ImportError:
    HAVE_PYDEEP = False

try:
    import yara
    HAVE_YARA = True
except ImportError:
    HAVE_YARA = False

# try:
#     import pefile
#     HAVE_PEFILE = True
# except ImportError:
#     HAVE_PEFILE = False

# try:
#     import androguard
#     HAVE_ANDROGUARD = True
# except ImportError:
#     HAVE_ANDROGUARD = False

FILE_CHUNK_SIZE = 16 * 1024

URL_REGEX = (
    # HTTP/HTTPS.
    "(https?:\\/\\/)"
    "((["
    # IP address.
    "(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\."
    "(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\."
    "(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\."
    "(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])]|"
    # Or domain name.
    "[a-zA-Z0-9\\.-]+)"
    # Optional port.
    "(\\:\\d+)?"
    # URI.
    "(/[\\(\\)a-zA-Z0-9_:%?=/\\.-]*)?"
)

domains = set()

def is_whitelisted_domain(domain):
    return domain in domains

# Initialize the domain whitelist.
for domain in open("domain.txt"):
    domains.add(domain.strip())


class File(object):
    """Basic file object class with all useful utilities."""

    # To be substituted with a category.
    YARA_RULEPATH = os.path.join("yara", "index_%s.yar")

    # static fields which indicate whether the user has been
    # notified about missing dependencies already
    notified_yara = False
    notified_pefile = False
    notified_androguard = False

    # Given that ssdeep hashes are not really used much in practice we're just
    # going to disable its warning by default for now.
    notified_pydeep = True

    # The yara rules should not change during one session of processing tasks,
    # thus we can cache them. If they are updated, one should restart Cuckoo
    # or the processing tasks.
    yara_rules = {}

    def __init__(self, file_path):
        """@param file_path: file path."""
        self.file_path = file_path

        # these will be populated when first accessed
        self._file_data = None
        self._crc32 = None
        self._md5 = None
        self._sha1 = None
        self._sha256 = None
        self._sha512 = None

    def get_name(self):
        """Get file name.
        @return: file name.
        """
        file_name = os.path.basename(self.file_path)
        return file_name

    def valid(self):
        return os.path.exists(self.file_path) and \
            os.path.isfile(self.file_path) and \
            os.path.getsize(self.file_path) != 0

    def get_data(self):
        """Read file contents.
        @return: data.
        """
        return self.file_data

    def get_chunks(self):
        """Read file contents in chunks (generator)."""

        with open(self.file_path, "rb") as fd:
            while True:
                chunk = fd.read(FILE_CHUNK_SIZE)
                if not chunk:
                    break
                yield chunk

    def calc_hashes(self):
        """Calculate all possible hashes for this file."""
        crc = 0
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        sha512 = hashlib.sha512()

        for chunk in self.get_chunks():
            crc = binascii.crc32(chunk, crc)
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
            sha512.update(chunk)

        self._crc32 = "".join("%02X" % ((crc >> i) & 0xff)
                              for i in [24, 16, 8, 0])
        self._md5 = md5.hexdigest()
        self._sha1 = sha1.hexdigest()
        self._sha256 = sha256.hexdigest()
        self._sha512 = sha512.hexdigest()

    @property
    def file_data(self):
        if not self._file_data:
            self._file_data = open(self.file_path, "rb").read()
        return self._file_data

    def get_size(self):
        """Get file size.
        @return: file size.
        """
        return os.path.getsize(self.file_path)

    def get_crc32(self):
        """Get CRC32.
        @return: CRC32.
        """
        if not self._crc32:
            self.calc_hashes()
        return self._crc32

    def get_md5(self):
        """Get MD5.
        @return: MD5.
        """
        if not self._md5:
            self.calc_hashes()
        return self._md5

    def get_sha1(self):
        """Get SHA1.
        @return: SHA1.
        """
        if not self._sha1:
            self.calc_hashes()
        return self._sha1

    def get_sha256(self):
        """Get SHA256.
        @return: SHA256.
        """
        if not self._sha256:
            self.calc_hashes()
        return self._sha256

    def get_sha512(self):
        """
        Get SHA512.
        @return: SHA512.
        """
        if not self._sha512:
            self.calc_hashes()
        return self._sha512

    def get_ssdeep(self):
        """Get SSDEEP.
        @return: SSDEEP.
        """
        if not HAVE_PYDEEP:
            if not File.notified_pydeep:
                File.notified_pydeep = True
                log.warning("Unable to import pydeep (install with `pip install pydeep`)")
            return None

        try:
            return pydeep.hash_file(self.file_path)
        except Exception:
            return None

    def get_type(self):
        """Get MIME file type.
        @return: file type.
        """
        file_type = None
        if HAVE_MAGIC:
            try:
                ms = magic.open(magic.MAGIC_NONE)
                ms.load()
                file_type = ms.file(self.file_path)
            except:
                try:
                    file_type = magic.from_file(self.file_path)
                except Exception as e:
                    log.debug("Error getting magic from file %s: %s",
                              self.file_path, e)
            finally:
                try:
                    ms.close()
                except:
                    pass

        if file_type is None:
            try:
                p = subprocess.Popen(["file", "-b", self.file_path],
                                     stdout=subprocess.PIPE)
                file_type = p.stdout.read().strip()
            except Exception as e:
                log.debug("Error running file(1) on %s: %s",
                          self.file_path, e)

        return file_type

    def get_content_type(self):
        """Get MIME content file type (example: image/jpeg).
        @return: file content type.
        """
        file_type = None
        if HAVE_MAGIC:
            try:
                ms = magic.open(magic.MAGIC_MIME)
                ms.load()
                file_type = ms.file(self.file_path)
            except:
                try:
                    file_type = magic.from_file(self.file_path, mime=True)
                except:
                    pass
            finally:
                try:
                    ms.close()
                except:
                    pass

        if file_type is None:
            try:
                args = ["file", "-b", "--mime-type", self.file_path]
                file_type = subprocess.check_output(args).strip()
            except:
                pass

        return file_type

    def _yara_encode_string(self, s):
        # Beware, spaghetti code ahead.
        try:
            new = s.encode("utf-8")
        except UnicodeDecodeError:
            s = s.lstrip("uU").encode("hex").upper()
            s = " ".join(s[i:i+2] for i in range(0, len(s), 2))
            new = "{ %s }" % s

        return new

    def _yara_matches_177(self, matches):
        """Extract matches from the Yara output for version 1.7.7."""
        ret = []
        for _, rule_matches in matches.items():
            for match in rule_matches:
                strings = set()

                for s in match["strings"]:
                    strings.add(self._yara_encode_string(s["data"]))

                ret.append({
                    "name": match["rule"],
                    "meta": match["meta"],
                    "strings": list(strings),
                })

        return ret

    def get_yara(self, category="binaries"):
        """Get Yara signatures matches.
        @return: matched Yara signatures.
        """
        results = []

        if not HAVE_YARA:
            if not File.notified_yara:
                File.notified_yara = True
                log.warning("Unable to import yara (please compile from sources)")
            return results

        # Compile the Yara rules only the first time.
        if category not in File.yara_rules:
            rulepath = self.YARA_RULEPATH % category
            if not os.path.exists(rulepath):
                log.warning("The specified rule file at %s doesn't exist, "
                            "skip", rulepath)
                return results

            try:
                File.yara_rules[category] = yara.compile(rulepath)
            except:
                log.exception("Error compiling the Yara rules.")
                return

        if not os.path.getsize(self.file_path):
            return results

        try:
            matches = File.yara_rules[category].match(self.file_path)

            if getattr(yara, "__version__", None) == "1.7.7":
                return self._yara_matches_177(matches)

            results = []

            for match in matches:
                strings = set()
                for s in match.strings:
                    strings.add(self._yara_encode_string(s[2]))

                results.append({
                    "name": match.rule,
                    "meta": match.meta,
                    "strings": list(strings),
                })

        except Exception as e:
            log.exception("Unable to match Yara signatures: %s", e)

        return results

    def get_urls(self):
        """Extract all URLs embedded in this file through a simple regex."""
        if not os.path.getsize(self.file_path):
            return []

        # http://stackoverflow.com/a/454589
        urls = set()
        f = open(self.file_path, "rb")
        m = mmap.mmap(f.fileno(), 0, access=mmap.PROT_READ)

        for url in re.findall(URL_REGEX, m):
            if not is_whitelisted_domain(url[1]):
                urls.add("".join(url))

        return list(urls)

    def get_all(self):
        """Get all information available.
        @return: information dict.
        """
        infos = {}
        infos["name"] = self.get_name()
        infos["path"] = self.file_path
        infos["size"] = self.get_size()
        infos["crc32"] = self.get_crc32()
        infos["md5"] = self.get_md5()
        infos["sha1"] = self.get_sha1()
        infos["sha256"] = self.get_sha256()
        infos["sha512"] = self.get_sha512()
        infos["ssdeep"] = self.get_ssdeep()
        infos["type"] = self.get_type()
        infos["yara"] = self.get_yara()
        infos["urls"] = self.get_urls()
        return infos