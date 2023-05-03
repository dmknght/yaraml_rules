import rzpipe  # import r2pipe if using radare2
# import io
import json


# https://r2wiki.readthedocs.io/en/latest/home/radare2-python-scripting/

class BinaryMetadata:
    def __init__(self, path="", quick_str=True):
        self.pointer = rzpipe.open(path, flags=["-2"])
        self.quick_str = quick_str
        self.section_hashes = []
        self.strings = []
        self.imports = []
        self.exports = []
        self.symbols = []

    def is_executable(self):
        file_type = self.pointer.cmd("e file.type").split("\n")[0]
        if file_type == "elf" or file_type == "pe":
            return True
        return False

    def get_checksum(self):
        return self.pointer.cmd("ph sha256").split("\n")[0]

    def get_symbols(self):
        # Get all symbols of binary
        symbols = json.loads(self.pointer.cmd("isj"))
        for each_symbol in symbols:
            # Real name too?
            self.symbols.append(each_symbol["name"])

    def get_section_hashes(self):
        # Get section hashes in md5
        section_hashes = json.loads(self.pointer.cmd("iSj -k md5"))
        for each_section in section_hashes:
            if "md5" in each_section:
                self.section_hashes.append(each_section["md5"])

    def get_imports(self):
        # Import hash attributes like type (func / ob). Need to check it?
        imports = json.loads(self.pointer.cmd("iij"))
        for each_import in imports:
            self.imports.append(each_import["name"])

    def get_exports(self):
        """
      name: xmrig::uv_async_t::~uv_async_t()
      real_name: _ZN5xmrig10uv_async_tD1Ev -> display in rizin
    """
        exports = json.loads(self.pointer.cmd("iEj"))
        for each_export in exports:
            self.exports.append(each_export["name"])

    def get_strings(self):
        # string_in_json = ""
        if self.quick_str:
            string_in_json = json.loads(self.pointer.cmd("izj"))
        else:
            string_in_json = json.loads(self.pointer.cmd("izzj"))

        if string_in_json:
            for each_string in string_in_json:
                self.strings.append(each_string["string"])

    def auto_analysis(self):
        self.get_section_hashes()
        self.get_imports()
        self.get_exports()
        self.get_strings()
        self.get_symbols()
        self.section_hashes = list(set(self.section_hashes))
        self.imports = list(set(self.imports))
        self.exports = list(set(self.exports))
        self.symbols = list(set(self.symbols))
        self.strings = list(set(self.strings))

    def get_result(self):
        """
      Get section hashes, strings, imports, exports, ... in dict
      Return deduplicated list
    """
        self.auto_analysis()

        meta_data = {}
        if self.section_hashes:
            meta_data["hashes"] = self.section_hashes
        if self.imports:
            meta_data["imports"] = self.imports
        if self.exports:
            meta_data["exports"] = self.exports
        if self.symbols:
            meta_data["symbols"] = self.symbols
        if self.strings:
            meta_data["strings"] = self.strings

        return meta_data
