    def zeroize(self):
        _MASTER_REGISTRY.add(self)
        
        try:
            trail = object.__getattribute__(self, 'audit_trail')
            if trail is not None:
                trail.append("ZEROIZED")
        except Exception:
            pass

        is_already_zeroized = object.__getattribute__(self, '_FailClosedEngine__is_zeroized')

        object.__setattr__(self, '_FailClosedEngine__is_zeroized', True)
        object.__setattr__(self, '_FailClosedEngine__terminal_state_locked', True)
        object.__setattr__(self, 'system_locked', True)
        object.__setattr__(self, 'secure_ram_key_status', "ZEROIZED")

        if not is_already_zeroized:
            try:
                key_buf = object.__getattribute__(self, '_FailClosedEngine__secure_ram_key')
            except AttributeError:
                key_buf = None

            if key_buf is not None:
                try:
                    buf_len = len(key_buf)
                    addr = ctypes.addressof((ctypes.c_char * buf_len).from_buffer(key_buf))
                    ctypes.memset(addr, 0x00, buf_len)
                    ctypes.memset(addr, 0xFF, buf_len)
                    ctypes.memset(addr, 0x00, buf_len)
                    for i in range(buf_len):
                        key_buf[i] = 0x00
                except Exception:
                    for i in range(len(key_buf)):
                        key_buf[i] = 0x00

            object.__setattr__(self, '_FailClosedEngine__secure_ram_key', None)

        return "ENGINE_ZEROIZED"
