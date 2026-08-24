    def check_admissibility(self) -> bool:
        # Class-level invariant check against dict reflection & fallback tampering (P0-03 Fix)
        raw_dict = object.__getattribute__(self, "__dict__")
        if (
            raw_dict.get("_TurkashEngine__is_zeroized", False) or
            raw_dict.get("_TurkashEngine__terminal_state_locked", False) or
            raw_dict.get("_TurkashEngine__system_locked", False) or
            raw_dict.get("_TurkashEngine__secure_ram_key") is None
        ):
            return False

        if self.__terminal_state_locked or self.__is_zeroized or self.__system_locked:
            return False
        if self.__secure_ram_key is None:
            return False
        memory_is_wiped = all(b == 0 for b in self.__secure_ram_key)
        if memory_is_wiped:
            return False
        return True

    def execute_critical_operation_mpa(self, required_count: int = 2) -> str:
        # Class-level invariant check against dict reflection & fallback tampering (P0-03 Fix)
        raw_dict = object.__getattribute__(self, "__dict__")
        if (
            raw_dict.get("_TurkashEngine__is_zeroized", False) or
            raw_dict.get("_TurkashEngine__terminal_state_locked", False) or
            raw_dict.get("_TurkashEngine__system_locked", False) or
            raw_dict.get("_TurkashEngine__secure_ram_key") is None
        ):
            raise PermissionError("CRITICAL_BLOCK: Terminal state zeroization is irreversible and fallback is denied.")

        if not self.check_admissibility():
            self._log_event("CRITICAL_OPERATION_DENIED", {"reason": "admissibility_boundary_failed_or_zeroized"})
            return "OPERATION_DENIED: Engine in terminal or locked state."

        if self.check_quorum(required_count):
            self._log_event("CRITICAL_OPERATION_AUTHORIZED", {"quorum": len(self.authorized_admins)})
            return "OPERATION_SUCCESS: Quorum reached."
        else:
            self._log_event("CRITICAL_OPERATION_DENIED", {"reason": "insufficient_signatures"})
            return "OPERATION_DENIED: Insufficient signatures."
