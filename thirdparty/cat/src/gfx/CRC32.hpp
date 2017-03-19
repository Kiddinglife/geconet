#ifndef CHECKSUMS_HPP
#define CHECKSUMS_HPP

//// CRC32Calculator

class CRC32Calculator
{
	u32 table[256];
	u32 reg;

public:
	CRC32Calculator(u32 polynomial);

	inline void begin() { reg = 0xffffffff; }
	void perform(const void *vbuf, u32 len);
	inline u32 finish() { return reg = ~reg; }

	inline u32 getRegister() { return reg; }
};



#endif // include guard
