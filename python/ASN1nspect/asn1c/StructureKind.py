from enum import IntFlag, Enum

class structure_type(IntFlag):
	LEGACY = 0
	LEGACY_WITH_APER = 1
	MODERN = 2
	MODERN_NO_OER = 3
	MODERN_NO_PER = 4
	MODERN_NEITHER = 5