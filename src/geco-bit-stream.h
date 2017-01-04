/*
 * Geco Gaming Company
 * All Rights Reserved.
 * Copyright (c)  2016 GECOEngine.
 *
 * GECOEngine is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * GECOEngine is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.

 * You should have received a copy of the GNU Lesser General Public License
 * along with KBEngine.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

 /*
  * geco-bit-stream.h
  *
  *  Created on: 15Jul.,2016
  *      Author: jackiez
  */

#ifndef SRC_COMMON_DS_GECO_BIT_STREAM_H_
#define SRC_COMMON_DS_GECO_BIT_STREAM_H_

#include <cstdio>
#include <stdlib.h>
#include <memory>
#include <cfloat>
#include <cstring>
#include <cmath>
#include <cassert>
#include <string>

#include <list>
#include <map>
#include <vector>

#include "geco-common.h"
#include "geco-malloc.h"

struct uint24_t
{
  unsigned int val;

  uint24_t() :
      val(0)
  {
  }
  operator unsigned int()
  {
    return val;
  }
  operator unsigned int() const
  {
    return val;
  }

  uint24_t(const uint24_t& a)
  {
    val = a.val;
  }
  uint24_t operator++()
  {
    ++val;
    val &= 0x00FFFFFF;
    return *this;
  }
  uint24_t operator--()
  {
    --val;
    val &= 0x00FFFFFF;
    return *this;
  }
  uint24_t operator++(int)
  {
    uint24_t temp(val);
    ++val;
    val &= 0x00FFFFFF;
    return temp;
  }
  uint24_t operator--(int)
  {
    uint24_t temp(val);
    --val;
    val &= 0x00FFFFFF;
    return temp;
  }
  uint24_t operator&(const uint24_t& a)
  {
    return uint24_t(val & a.val);
  }
  uint24_t& operator=(const uint24_t& a)
  {
    val = a.val;
    return *this;
  }
  uint24_t& operator+=(const uint24_t& a)
  {
    val += a.val;
    val &= 0x00FFFFFF;
    return *this;
  }
  uint24_t& operator-=(const uint24_t& a)
  {
    val -= a.val;
    val &= 0x00FFFFFF;
    return *this;
  }
  bool operator==(const uint24_t& right) const
  {
    return val == right.val;
  }
  bool operator!=(const uint24_t& right) const
  {
    return val != right.val;
  }
  bool operator >(const uint24_t& right) const
  {
    return val > right.val;
  }
  bool operator <(const uint24_t& right) const
  {
    return val < right.val;
  }
  const uint24_t operator+(const uint24_t &other) const
  {
    return uint24_t(val + other.val);
  }
  const uint24_t operator-(const uint24_t &other) const
  {
    return uint24_t(val - other.val);
  }
  const uint24_t operator/(const uint24_t &other) const
  {
    return uint24_t(val / other.val);
  }
  const uint24_t operator*(const uint24_t &other) const
  {
    return uint24_t(val * other.val);
  }

  uint24_t(const unsigned int& a)
  {
    val = a;
    val &= 0x00FFFFFF;
  }
  uint24_t operator&(const unsigned int& a)
  {
    return uint24_t(val & a);
  }
  uint24_t& operator=(const unsigned int& a)
  {
    val = a;
    val &= 0x00FFFFFF;
    return *this;
  }
  uint24_t& operator+=(const unsigned int& a)
  {
    val += a;
    val &= 0x00FFFFFF;
    return *this;
  }
  uint24_t& operator-=(const unsigned int& a)
  {
    val -= a;
    val &= 0x00FFFFFF;
    return *this;
  }
  bool operator==(const unsigned int& right) const
  {
    return val == (right & 0x00FFFFFF);
  }
  bool operator!=(const unsigned int& right) const
  {
    return val != (right & 0x00FFFFFF);
  }
  bool operator >(const unsigned int& right) const
  {
    return val > (right & 0x00FFFFFF);
  }
  bool operator <(const unsigned int& right) const
  {
    return val < (right & 0x00FFFFFF);
  }
  const uint24_t operator+(const unsigned int &other) const
  {
    return uint24_t(val + other);
  }
  const uint24_t operator-(const unsigned int &other) const
  {
    return uint24_t(val - other);
  }
  const uint24_t operator/(const unsigned int &other) const
  {
    return uint24_t(val / other);
  }
  const uint24_t operator*(const unsigned int &other) const
  {
    return uint24_t(val * other);
  }
};

  // MSWin uses _copysign, others use copysign...
#ifndef _WIN32
#define _copysign copysign
#endif

#define UnSignedInteger true
#define SignedInteger false

/// Threshold at which to do a malloc / free rather than pushing data onto a fixed stack
/// for the bitstream class. 512 is an arbitrary size, just picking something likely to be larger
/// than  most packets
#define GECO_STREAM_STACK_ALLOC_BYTES 1472
#define GECO_STREAM_STACK_ALLOC_BITS (BYTES_TO_BITS(GECO_STREAM_STACK_ALLOC_BYTES))

// another imple of singleton using static methods instead of inhertance
#define GECO_STATIC_FACTORY_DELC(TYPE)\
static TYPE* get_instance(void);\
static void reclaim_instance(TYPE *i)
#define GECO_STATIC_FACTORY_DEFIS(FATHER_TYPE, CHILD_TYPE)\
FATHER_TYPE* FATHER_TYPE::get_instance(void){ return new CHILD_TYPE;}\
void FATHER_TYPE::reclaim_instance(FATHER_TYPE* i){ delete i;}

/// Given a number of bits,
/// return how many bytes are needed to hold all bits.
/// For example, 17 bits will need 3 bytes to hold.
#define BITS_TO_BYTES(x) (((x)+7)>>3)
#define BYTES_TO_BITS(x) ((x)<<3)

typedef uint32 bit_size_t;
typedef uint32 byte_size_t;

class uint24_t;
class geco_bit_stream_t;

/// JackieStringCompressor

///  [Internal] A single node in the Huffman Encoding Tree.
struct HuffmanEncodingTreeNode {
	unsigned char value;
	unsigned weight;
	HuffmanEncodingTreeNode *left;
	HuffmanEncodingTreeNode *right;
	HuffmanEncodingTreeNode *parent;
};
/// Used to hold bit encoding for one character
struct CharacterEncoding {
	unsigned char* encoding;
	unsigned short bitLength;
};
/// This generates special cases of the huffman encoding tree using 8 bit keys
/// with the additional condition that unused combinations of 8 bits are treated as a frequency of 1
class HuffmanEncodingTree {

public:
	HuffmanEncodingTree();
	~HuffmanEncodingTree();

	/// \brief Pass an array of bytes to array and a preallocated JackieBits to receive the output.
	/// \param [in] input Array of bytes to encode
	/// \param [in] sizeInBytes size of \a input
	/// \param [out] output The bitstream to write to
	void EncodeArray(unsigned char *input, size_t sizeInBytes,
		geco_bit_stream_t * output);

	/// \brief Decodes an array encoded by EncodeArray().
	unsigned DecodeArray(geco_bit_stream_t * input, bit_size_t sizeInBits,
		size_t maxCharsToWrite, unsigned char *output);
	void DecodeArray(unsigned char *input, bit_size_t sizeInBits,
		geco_bit_stream_t * output);

	/// \brief Given a frequency table of 256 elements, all with a frequency of 1 or more, generate the tree.
	void GenerateFromFrequencyTable(const unsigned int frequencyTable[256] = 0);

	/// \brief Free the memory used by the tree.
	void FreeMemory(void);

private:
	/// The root node of the tree
	HuffmanEncodingTreeNode *root;
	CharacterEncoding encodingTable[256];
	std::vector<CharacterEncoding*> encodingTableSorted;
};

class geco_string_compressor_t {
private:
	/// Singleton instance
	static geco_string_compressor_t *instance;
	/// Pointer to the huffman encoding trees.
	//std::map<int, HuffmanEncodingTree*> huffmanEncodingTrees;
	std::vector<HuffmanEncodingTree*> huffmanEncodingTrees;
	static int referenceCount;

public:
	geco_string_compressor_t();
	virtual ~geco_string_compressor_t();

	/// static function because only static functions can access static members
	/// The RakPeer constructor adds a reference to this class, so don't call this until an instance of RakPeer exists, or unless you call AddReference yourself.
	/// \return the unique instance of the JackieStringCompressor
	static geco_string_compressor_t* Instance(void);

	/// Given an array of strings, such as a chat log, generate the optimal encoding tree for it.
	/// This function is optional and if it is not called a default tree will be used instead.
	/// \param[in] input An array of bytes which should point to text.
	/// \param[in] inputLength Length of \a input
	/// \param[in] languageID An identifier for the language / string table to generate the tree for.  English is automatically created with ID 0 in the constructor.
	void GenerateTreeFromStrings(unsigned char *input, unsigned inputLength,
		uchar languageId);

	/// Writes input to output, compressed.  Takes care of the null terminator for you.
	/// \param[in] input Pointer to an ASCII string
	/// \param[in] maxCharsToWrite The max number of bytes to write of \a input.  Use 0 to mean no limit.
	/// \param[out] output The bitstream to write the compressed string to
	/// \param[in] languageID Which language to use
	void EncodeString(const char *input, int maxCharsToWrite,
		geco_bit_stream_t *output, uchar languageId = 0);

	/// Writes input to output, uncompressed.  Takes care of the null terminator for you.
	/// \param[out] output A block of bytes to receive the output
	/// \param[in] maxCharsToWrite Size, in bytes, of \a output .  A NULL terminator will always be appended to the output string.  If the maxCharsToWrite is not large enough, the string will be truncated.
	/// \param[in] input The bitstream containing the compressed string
	/// \param[in] languageID Which language to use
	bool DecodeString(char *output, int maxCharsToWrite,
		geco_bit_stream_t *input, uchar languageId = 0);

	void EncodeString(const std::string &input, int maxCharsToWrite,
		geco_bit_stream_t *output, uchar languageId = 0);
	bool DecodeString(std::string *output, int maxCharsToWrite,
		geco_bit_stream_t *input, uchar languageId = 0);

	/// Used so I can allocate and deallocate this singleton at runtime
	static void AddReference(void);
	/// Used so I can allocate and deallocate this singleton at runtime
	static void RemoveReference(void);
};

//! This class allows you to write and read native types as a string of bits.
//! the value of @mWritePosBits always reprsents
//! the position where a bit is going to be written(not been written yet)
//! the value of @curr_readable_pos always reprsents
//! the position where a bit is going to be read(not been read yet)
//! both of them will start to cout at index of 0,
//! so mWritePosBits = 2 means the first 2 bits (index 0 and 1) has been written,
//! the third bit (index 2) is being written (not been written yet)
//! so curr_readable_pos = 2 means the first 2 bits (index 0 and 1) has been read,
//! the third bit (index 2) is being read (not been read yet)
//! |                  8 bits               |                  8 bits                |
//!+++++++++++++++++++++++++++++++++++
//! | 0 |  1 | 2 | 3 |  4 | 5 |  6 | 7 | 8 | 9 |10 |11 |12 |13 |14 |15 |   bit index
//!+++++++++++++++++++++++++++++++++++
//! | 0 |  0 | 0 | 1 |  0 | 0 |  0 | 0 | 1 | 0 | 0  | 0 | 0  |  0 |  0 | 0  |  bit in memory
//!+++++++++++++++++++++++++++++++++++
//!
//! Assume given @mWritePosBits = 12, @curr_readable_pos = 2,
//! base on draw above,
//! all the unwritten bits are 4 bits at index 12 to 15,
//! all the written bits are 12 bits at index 0 - 11
//! all the unread bits are 10 bits (0100001000, index 2 to 11),
//!
//! Based on above, we can calculate:
//! index of byte that @curr_readable_pos points to is:
//! 0 = @curr_readable_pos >> 3 = 2/8 = index 0, data[0]
//! index of byte that @mWritePosBits points to is:
//! 1 = @mWritePosBits >> 3 = 12/8 = index 1, data[1]
//!
//! offset of byte boundary behind @curr_readable_pos is:
//! curr_readable_pos mods 8 =  curr_readable_pos & 7 = 2 &7 = 2 bits (00 at index 0,1)
//! offset of byte boundary behind mWritePosBits is:
//! mWritePosBits mod 8 = mWritePosBits & 7 = 12 &7 = 4 bits (1000 at index 8,9,10,11)
//!
//! BITS_TO_BYTES for mWritePosBits (bit at index 12 is exclusive) is:
//! (12+7) >> 3 = 19/8 = 2 ( also is the number of written bytes)
//! BITS_TO_BYTES(8[bit at index 8 is exclusive ])  =
//! (8+7)>>3 = 15/8 = 1 ( also is the number of written bytes)
//!
class geco_bit_stream_t {
private:
	bit_size_t allocated_bits_size_;
	bit_size_t writable_bit_pos_;
	bit_size_t readable_bit_pos_;
	uchar *uchar_data_;
	/// true if @data is pointint to heap-memory pointer,
	/// false if it is stack-memory  pointer
	bool can_free_;
	/// true if writting not allowed in which case all write functions will not work
	/// false if writting is allowed
	bool is_read_only_;
	uchar statck_buffer_[GECO_STREAM_STACK_ALLOC_BYTES];

public:
	GECO_STATIC_FACTORY_DELC(geco_bit_stream_t);

	/// @Param [in] [ bit_size_t initialBytesAllocate]:
	/// the number of bytes to pre-allocate.
	/// @Remarks:
	/// Create the JackieBits, with some number of bytes to immediately
	/// allocate. There is no benefit to calling this, unless you know exactly
	/// how many bytes you need and it is greater than 256.
	/// @Author mengdi[Jackie]
	geco_bit_stream_t(const bit_size_t initialBytesAllocate);

	/// @brief  Initialize by setting the @data to a predefined pointer.
	/// @access  public
	/// @param [in] [uchar * src]
	/// @param [in] [const  byte_size_t len]  unit of byte
	/// @param [in] [bool copy]
	/// true to make an deep copy of the @src .
	/// false to just save a pointer to the @src.
	/// @remarks
	/// 99% of the time you will use this function to read Packet:;data,
	/// in which case you should write something as follows:
	/// JACKIE_INET::JackieStream js(packet->data, packet->length, false);
	/// @author mengdi[Jackie]
	geco_bit_stream_t(uchar* src, const byte_size_t len, bool copy = false);

	/// DEFAULT CTOR
	geco_bit_stream_t();

	/// realloc and free are more efficient than delete and new
	/// because it will not call ctor and dtor
	~geco_bit_stream_t();

	/// Getters and Setters
	bit_size_t writable_bit_pos() const {
		return writable_bit_pos_;
	}
	bit_size_t writable_byte_pos() const {
		return BITS_TO_BYTES(writable_bit_pos_);
	}
	bit_size_t readable_bit_pos() const {
		return readable_bit_pos_;
	}
	uchar* uchar_data() const {
		return uchar_data_;
	}
	char* char_data() const {
		return (char*)uchar_data_;
	}
	void uchar_data(uchar* val) {
		uchar_data_ = val;
		is_read_only_ = true;
	}
	void writable_bit_pos(bit_size_t val) {
		writable_bit_pos_ = val;
	}
	void readable_bit_pos(bit_size_t val) {
		readable_bit_pos_ = val;
	}
	void allocated_bits_size(bit_size_t val) {
		allocated_bits_size_ = val;
	}

	/// @Brief  Resets for reuse.
	/// @Access  public
	/// @Notice
	/// Do NOT reallocate memory because JackieStream is used
	/// to serialize/deserialize a buffer. Reallocation is a dangerous
	/// operation (may result in leaks).
	/// @author mengdi[Jackie]
	inline void reset(void) {
		writable_bit_pos_ = readable_bit_pos_ = 0;
	}

	///@brief Sets the read pointer back to the beginning of your data.
	/// @access public
	/// @author mengdi[Jackie]
	inline void reset_readable_bit_pos(void) {
		readable_bit_pos_ = 0;
	}

	/// @brief Sets the write pointer back to the beginning of your data.
	/// @access public
	/// @author mengdi[Jackie]
	inline void reset_writable_bit_pos(void) {
		writable_bit_pos_ = 0;
	}

	/// @brief this is good to call when you are done with the stream to make
	/// sure you didn't leave any data left over void
	/// should hit if reads didn't match writes
	/// @access public
	/// @author mengdi[Jackie]
	inline void AssertStreamEmpty(void) {
		assert(readable_bit_pos_ == writable_bit_pos_);
	}

	///@brief payload are actually the unread bits wriitten bits - read_bits
	/// @access public
	inline bit_size_t get_payloads(void) const {
		return writable_bit_pos_ - readable_bit_pos_;
	}

	///@brief the number of bytes needed to  hold all the written bits
	/// @access public
	///@notice
	/// particial byte is also accounted and the bit at index @param
	/// mWritePosBits is exclusive).
	/// if mWritingPosBits =12, will need 2 bytes to hold 12 written bits (6 bits wasted)
	/// if mWritingPosBits = 8, will need 1 byte to hold 8 written bits (0 bits wasted)
	/// @author mengdi[Jackie]
	inline byte_size_t get_written_bytes(void) const {
		return BITS_TO_BYTES(writable_bit_pos_);
	}

	/// @brief get the number of written bits
	/// will return same value to that of writable_bit_pos()
	/// @access public
	/// @author mengdi[Jackie]
	inline bit_size_t get_written_bits(void) const {
		return writable_bit_pos_;
	}

	/// @method align_readable_bit_pos
	/// @access public
	/// @returns void
	/// @param [in] void
	/// @brief align the next read to a byte boundary.
	/// @notice
	/// this can be used to 'waste' bits to byte align for efficiency reasons It
	/// can also be used to force coalesced bitstreams to start on byte
	/// boundaries so so WriteAlignedBits and ReadAlignedBits both
	/// calculate the same offset when aligning.
	/// @see
	inline void align_readable_bit_pos(void) {
		readable_bit_pos_ += 8 - (((readable_bit_pos_ - 1) & 7) + 1);
	}

	/// @method Read
	/// @access public
	/// @returns void
	/// @param [in] char * output
	/// The result byte array. It should be larger than @em numberOfBytes.
	/// @param [in] const unsigned int numberOfBytes  The number of byte to read
	/// @brief Read an array of raw data or casted stream of byte.
	/// @notice The array is raw data.
	/// There is no automatic endian conversion with this function
	void ReadRaw(char* output, const unsigned int numberOfBytes) {
		ReadBits((uchar*)output, BYTES_TO_BITS(numberOfBytes));
	}
	void ReadRaw(uchar* output, const unsigned int numberOfBytes) {
		ReadBits(output, BYTES_TO_BITS(numberOfBytes));
	}

	/// @func   ReadBits
	/// @brief   Read numbers of bit into dest array
	/// @access public
	/// @param [out] [unsigned uchar * dest]  The destination array
	/// @param [in] [bit_size_t bitsRead] The number of bits to read
	/// @param [in] [const bool alignRight]  the alignment of dest byte
	/// If true bits will be right aligned. otherwise, no shofts
	/// @returns void
	/// @remarks
	/// 1.jackie stream internal data are aligned to the left side of byte boundary.so alignRight should be false
	/// 2.user data are aligned to the right side of byte boundary, so alignRight shouldbe true
	/// @notice
	/// 1.use True to read to user data
	/// 2.use False to read this stream to another stream
	/// @author mengdi[Jackie]
	void ReadBits(uchar *dest, bit_size_t bitsRead, bool alignRight = true);

	/// @method Read
	/// @access public
	/// @returns void
	/// @param [in] IntegralType & outTemplateVar
	/// @brief Read any integral type from a bitstream.
	/// Define DO_NOT_SWAP_ENDIAN if you need endian swapping.
	template<class IntegralType>
	inline void Read(IntegralType &dest) {
		if (sizeof(IntegralType) == 1)
			ReadBits((uchar*)&dest, sizeof(IntegralType) * 8, true);
		else {
#ifndef DO_NOT_SWAP_ENDIAN
			if (DoEndianSwap()) {
				uchar output[sizeof(IntegralType)];
				ReadBits(output, BYTES_TO_BITS(sizeof(IntegralType)), true);
				ReverseBytes(output, (uchar*)&dest, sizeof(IntegralType));
			}
			else {
				ReadBits((uchar*)&dest, BYTES_TO_BITS(sizeof(IntegralType)),
					true);
			}
#else
			ReadBits((uchar*)&dest, BYTES_TO_BITS(sizeof(IntegralType)), true);
#endif
		}
		}

	/// @method Read
	/// @access public
	/// @returns void
	/// @param [in] bool & dest The value to read
	/// @brief  Read a bool from a bitstream.
	inline void Read(bool &dest) {
		assert(get_payloads() >= 1);
		//if (get_payloads() < 1) return;
		dest = (uchar_data_[readable_bit_pos_ >> 3]
			& (0x80 >> (readable_bit_pos_ & 7))) != 0;
		readable_bit_pos_++;
	}

	inline void Read(float &dest) {
		assert(get_payloads() >= sizeof(int));
		int v;
		Read(v);
		//dest = fabs(BitsToFloat(v));
		dest = fabs(BitsToFloat(v));
	}

	/// TODO MOVE THIS into network_address_t by operator <<
	/// @method Read
	/// @access public
	/// @returns void
	/// @param [in] NetworkAddress & dest The value to read
	/// @brief Read a NetworkAddress from a bitstream.
//        inline void Read(network_address_t &dest)
//        {
//            uchar ipVersion;
//            Read(ipVersion);
//            if (ipVersion == 4)
//            {
//                dest.address.addr4.sin_family = AF_INET;
//                // Read(var.binaryAddress);
//                // Don't endian swap the address or port
//                uint binaryAddress;
//                ReadBits((uchar*) &binaryAddress,
//                        BYTES_TO_BITS(sizeof(binaryAddress)), true);
//                // Unhide the IP address, done to prevent routers from changing it
//                dest.address.addr4.sin_addr.s_addr = ~binaryAddress;
//                ReadBits((uchar*) &dest.address.addr4.sin_port,
//                        BYTES_TO_BITS(sizeof(dest.address.addr4.sin_port)),
//                        true);
//                dest.debugPort = ntohs(dest.address.addr4.sin_port);
//            }
//            else
//            {
//#if NET_SUPPORT_IPV6==1
//                ReadBits((uchar*)&dest.address.addr6, BYTES_TO_BITS(sizeof(dest.address.addr6)), true);
//                dest.debugPort = ntohs(dest.address.addr6.sin6_port);
//                //return b;
//#else
//                //return false;
//#endif
//            }
//        }
	/// @func Read
	/// @brief read three bytes into stream
	/// @access  public
	/// @param [in] [const uint24_t & inTemplateVar]
	/// @return [void]
	/// @remark
	/// @notice will align @mReadPosBIts to byte-boundary internally
	/// @see  align_readable_bit_pos()
	/// @author mengdi[Jackie]
	inline void Read(uint24_t &dest) {
		assert(get_payloads() >= 24);
		//if (get_payloads() < 24) return;
		if (!IsBigEndian()) {
			ReadBits((uchar *)&dest.val, 24, false);
			((uchar *)&dest.val)[3] = 0;
		}
		else {
			ReadBits((uchar *)&dest.val, 24, false);
			ReverseBytes((uchar *)&dest.val, 3);
			((uchar *)&dest.val)[0] = 0;
		}
	}

	/// TODO MOVE THIS into network_address_t by operator <<
	//inline void Read(guid_t &dest)
	//{
	//    return Read(dest.g);
	//}
	//inline bool Read(RakWString &outTemplateVar)
	//{
	//  return outTemplateVar.Deserialize(this);
	//}

	inline void Read(std::string&varString, bool readLanguageId = false) {
		uchar languageId;
		if (readLanguageId)
			ReadMini(languageId);
		else
			languageId = 0;
		geco_string_compressor_t::Instance()->DecodeString(&varString, 0xFFFF,
			this, languageId);
	}
	inline void Read(uchar *varString, bool readLanguageId = false) {
		Read((char*)varString, readLanguageId);
	}
	inline void Read(char *varString, bool readLanguageId = false) {
		uchar languageId;
		if (readLanguageId)
			ReadMini(languageId);
		else
			languageId = 0;
		geco_string_compressor_t::Instance()->DecodeString(varString, 0xFFFF,
			this, languageId);
	}
	//
	//inline bool Read(wchar_t *&varString)
	//{
	//  return RakWString::Deserialize(varString, this);
	//}

	/// @brief Read any integral type from a bitstream.
	/// @details If the written value differed from the value
	/// compared against in the write function,
	/// var will be updated.  Otherwise it will retain the current value.
	/// ReadDelta is only valid from a previous call to WriteDelta
	/// @param[in] outTemplateVar The value to read
	template<class IntegralType>
	inline void ReadChangedValue(IntegralType &dest) {
		bool dataWritten;
		Read(dataWritten);
		if (dataWritten)
			Read(dest);
	}

	/// @Brief Assume the input source points to a compressed native type.
	/// Decompress and read it.
	void ReadMini(uchar* dest, const bit_size_t bits2Read,
		const bool isUnsigned);

	/// @method ReadMini
	/// @access public
	/// @returns void
	/// @param [in] IntegralType & dest
	/// @brief Read any integral type from a bitstream,
	/// endian swapping counters internally. default is unsigned (isUnsigned = true)
	/// @notice
	/// For floating point, this is lossy, using 2 bytes for a float and 4 for
	/// a double.  The range must be between -1 and +1.
	/// For non-floating point, this is lossless, but only has benefit if you
	/// use less than half the bits of the type
	template<class IntegralType>
	inline void ReadMini(IntegralType &dest, bool isUnsigned = true) {
		ReadMini((uchar*)&dest, BYTES_TO_BITS(sizeof(IntegralType)),
			isUnsigned);
	}

	/// TODO MOVE THIS into network_address_t by operator <<
	//        inline void ReadMini(network_address_t &dest)
	//        {
	//            uchar ipVersion;
	//            ReadMini(ipVersion);
	//            if (ipVersion == 4)
	//            {
	//                dest.address.addr4.sin_family = AF_INET;
	//                // Read(var.binaryAddress);
	//                // Don't endian swap the address or port
	//                uint binaryAddress;
	//                ReadMini(binaryAddress);
	//                // Unhide the IP address, done to prevent routers from changing it
	//                dest.address.addr4.sin_addr.s_addr = ~binaryAddress;
	//                ReadMini(dest.address.addr4.sin_port);
	//                dest.debugPort = ntohs(dest.address.addr4.sin_port);
	//            }
	//            else
	//            {
	//#if NET_SUPPORT_IPV6==1
	//                ReadMini(dest.address.addr6);
	//                dest.debugPort = ntohs(dest.address.addr6.sin6_port);
	//#endif
	//            }
	//        }
	inline void ReadMini(uint24_t &dest) {
		ReadMini(dest.val);
	}

	inline void ReadMini(bool &dest) {
		Read(dest);
	}

	/// TODO MOVE THIS into network_address_t by operator <<
	//        inline void ReadMini(guid_t &dest)
	//        {
	//            ReadMini(dest.g);
	//        }

	//inline void ReadMiniTo(RakWString &outTemplateVar)
	//{
	//   outTemplateVar.ReadMini(this);
	//}

	inline void ReadMini(std::string &outTemplateVar) {
		//outTemplateVar.ReadMini(this, false);
	}
	inline void ReadMini(char *&outTemplateVar) {
		//GecoString::ReadMini(outTemplateVar, this, false);
	}
	inline void ReadMiniTo(wchar_t *&outTemplateVar)
	{
		//return RakWString::Deserialize(outTemplateVar, this);
	}

	inline void ReadMini(uchar *&outTemplateVar) {
		//GecoString::ReadMini((char*)outTemplateVar, this, false);
	}

	template<class srcType, class destType>
	void ReadCasted(destType &value) {
		srcType val;
		Read(val);
		value = (destType)val;
	}

	/// @method ReadMiniChanged
	/// @access public
	/// @returns void
	/// @param [in] templateType & dest
	/// @brief Read any integral type from a bitstream.
	/// If the written value differed from the value compared against in
	/// the write function, var will be updated.  Otherwise it will retain the
	/// current value. the current value will be updated.
	/// @notice
	/// For floating point, this is lossy, using 2 bytes for a float and 4 for a
	/// double.  The range must be between -1 and +1. For non-floating point,
	/// this is lossless, but only has benefit if you use less than half the bits of the
	/// type.  If you are not using DO_NOT_SWAP_ENDIAN the opposite is true for
	/// types larger than 1 byte
	/// @see
	template<class IntegralType>
	inline void ReadMiniChanged(IntegralType &dest) {
		bool dataWritten;
		Read(dataWritten);
		if (dataWritten)
			ReadMini(dest);
	}

	/// @brief Read a bool from a bitstream.
	/// @param[in] outTemplateVar The value to read
	inline void ReadMiniChanged(bool &dest) {
		Read(dest);
	}

	template<class IntegerType>
	void ReadIntegerRange(IntegerType &value, const IntegerType minimum,
		const IntegerType maximum, bool allowOutsideRange = false) {
		/// get the high byte bits size
		IntegerType diff = maximum - minimum;
		int requiredBits = BYTES_TO_BITS(sizeof(IntegerType))
			- get_leading_zeros_size(diff);
		ReadIntegerRange(value, minimum, maximum, requiredBits,
			allowOutsideRange);
	}

	/// @method ReadBitsIntegerRange
	/// @access public
	/// @returns void
	/// @param [in] templateType & value
	/// @param [in] const templateType minimum
	/// @param [in] const templateType maximum
	/// @param [in] const int requiredBits the value of bits to read
	/// @param [in] bool allowOutsideRange
	/// if true, we directly read it
	/// @brief
	/// @notice
	/// This is how we write value
	/// Assume@valueBeyondMini's value is 0x000012
	///------------------> Memory Address
	///+++++++++++
	///| 00 | 00 | 00 | 12 |  Big Endian
	///+++++++++++
	///+++++++++++
	///| 12 | 00 | 00 | 00 |  Little Endian
	///+++++++++++
	/// so for big endian, we need to reverse byte so that
	/// the high byte of 0x00 that was put in low address can be written correctly
	/// for little endian, we do nothing.
	/// After reverse bytes:
	///+++++++++++
	///| 12 | 00 | 00 | 00 |  Big Endian
	///+++++++++++
	///+++++++++++
	///| 12 | 00 | 00 | 00 |  Little Endian
	///+++++++++++
	/// When reading it, we have to reverse it back fro big endian
	/// we do nothing for little endian.
	/// @see
	template<class templateType>
	void ReadIntegerRange(templateType &value, const templateType minimum,
		const templateType maximum, const int requiredBits,
		bool allowOutsideRange) {
		assert(maximum >= minimum);

		if (allowOutsideRange) {
			bool isOutsideRange;
			Read(isOutsideRange);
			if (isOutsideRange) {
				ReadMini(value);
				return;
			}
		}

		value = 0;
		ReadBits((uchar*)&value, requiredBits, true);
		if (IsBigEndian()) {
			ReverseBytes((uchar*)&value, sizeof(value));
		}
		value += minimum;
	}

	/// @method Read
	/// @access public
	/// @returns void
	/// @param [in] float & outFloat The float to read
	/// @param [in] float floatMin  Predetermined minimum value of f
	/// @param [in] float floatMax Predetermined maximum value of f
	/// @brief
	/// Read a float into 2 bytes, spanning the range between
	/// @param floatMin and @param floatMax
	/// @notice
	/// @see
	void read_ranged_float(float &outFloat, float floatMin, float floatMax);

	/// @brief Read bytes, starting at the next aligned byte.
	/// @details Note that the modulus 8 starting offset of the sequence
	/// must be the same as was used with WriteBits. This will be a problem
	/// with packet coalescence unless you byte align the coalesced packets.
	/// @param[in] dest The byte array larger than @em numberOfBytesRead
	/// @param[in] bytes2Read The number of byte to read from the internal state
	/// @return true if there is enough byte.
	void ReadAlignedBytes(uchar *dest, const byte_size_t bytes2Read);

	/// @brief Reads what was written by write_aligned_bytes.
	/// @param[in] inOutByteArray The data
	/// @param[in] maxBytesRead Maximum number of bytes to read
	/// @return true on success, false on failure.
	void ReadAlignedBytes(char *dest, byte_size_t &bytes2Read,
		const byte_size_t maxBytes2Read);

	/// @method ReadAlignedBytesAlloc
	/// @access public
	/// @returns void
	/// @param [in] char * * dest  will be deleted if it is not a pointer to 0
	/// @param [in] byte_size_t & bytes2Read
	/// @param [in] const byte_size_t maxBytes2Read
	/// @brief  Same as ReadAlignedBytesSafe() but allocates the memory
	/// for you using new, rather than assuming it is safe to write to
	void ReadAlignedBytesAlloc(char **dest, byte_size_t &bytes2Read,
		const byte_size_t maxBytes2Read);

	// @brief return 1 if the next data read is a 1, 0 if it is a 0
	///@access public
	inline uint ReadBit(void) {
		uint result =
			((uchar_data_[readable_bit_pos_ >> 3]
				& (0x80 >> (readable_bit_pos_ & 7))) != 0) ? 1 : 0;
		readable_bit_pos_++;
		return result;
	}

	/// @access public
	/// @brief Read a normalized 3D vector, using (at most) 4 bytes
	/// + 3 bits instead of 12-24 bytes.
	/// @details Will further compress y or z axis aligned vectors.
	/// Accurate to 1/32767.5.
	/// @param[in] x x
	/// @param[in] y y
	/// @param[in] z z
	/// @return void
	/// @notice templateType for this function must be a float or double
	template<class templateType>
	void ReadNormVector(templateType &x, templateType &y) {
		read_ranged_float(x, -1.0f, 1.0f);
		read_ranged_float(y, -1.0f, 1.0f);
	}
	template<class templateType>
	void ReadNormVector(templateType &x, templateType &y, templateType &z) {
		read_ranged_float(x, -1.0f, 1.0f);
		read_ranged_float(y, -1.0f, 1.0f);
		read_ranged_float(z, -1.0f, 1.0f);
	}

	/// @brief Read 3 floats or doubles, using 10 bytes,
	/// where those float or doubles comprise a vector.
	/// @details Loses accuracy to about 3/10ths and only saves 2 bytes,
	/// so only use if accuracy is not important.
	/// @param[in] x x
	/// @param[in] y y
	/// @param[in] z z
	/// @return void
	/// @notice templateType for this function must be a float or double
	template<class templateType>
	void ReadVector(templateType &x, templateType &y) {
		float magnitude;
		Read(magnitude);

		if (magnitude > 0.00001f) {
			ReadMini(x);
			ReadMini(y);
			x *= magnitude;
			y *= magnitude;
		}
		else {
			x = 0.0;
			y = 0.0;
		}
	}
	template<class templateType>
	void ReadVector(templateType &x, templateType &y, templateType &z) {
		float magnitude;
		Read(magnitude);

		if (magnitude > 0.00001f) {
			ReadMini(x);
			ReadMini(y);
			ReadMini(z);
			x *= magnitude;
			y *= magnitude;
			z *= magnitude;
		}
		else {
			x = 0.0;
			y = 0.0;
			z = 0.0;
		}
	}

	/// @brief Read a normalized quaternion in 6 bytes + 4 bits instead of 16 bytes.
	/// @param[in] w w
	/// @param[in] x x
	/// @param[in] y y
	/// @param[in] z z
	/// @return void
	/// @notice templateType for this function must be a float or double
	template<class templateType>
	void ReadNormQuat(templateType &w, templateType &x, templateType &y,
		templateType &z) {
		bool cwNeg = false, cxNeg = false, cyNeg = false, czNeg = false;
		Read(cwNeg);
		Read(cxNeg);
		Read(cyNeg);
		Read(czNeg);

		ushort cx, cy, cz;
		ReadMini(cx);
		ReadMini(cy);
		ReadMini(cz);

		// Calculate w from x,y,z
		x = (templateType)(cx / 65535.0);
		y = (templateType)(cy / 65535.0);
		z = (templateType)(cz / 65535.0);

		if (cxNeg)
			x = -x;
		if (cyNeg)
			y = -y;
		if (czNeg)
			z = -z;

		float difference = 1.0f - x * x - y * y - z * z;
		if (difference < 0.0f)
			difference = 0.0f;

		w = (templateType)(sqrt(difference));
		if (cwNeg)
			w = -w;
	}

	/// @brief Read an orthogonal matrix from a quaternion,
	/// reading 3 components of the quaternion in 2 bytes each and
	/// extrapolatig the 4th.
	/// @details Use 6 bytes instead of 36
	/// Lossy, although the result is renormalized
	/// @return true on success, false on failure.
	///@notice templateType for this function must be a float or double
	template<class templateType>
	void ReadOrthMatrix(templateType &m00, templateType &m01, templateType &m02,
		templateType &m10, templateType &m11, templateType &m12,
		templateType &m20, templateType &m21, templateType &m22) {
		float qw, qx, qy, qz;
		ReadNormQuat(qw, qx, qy, qz);

		// Quat to orthogonal rotation matrix
		// http://www.euclideanspace.com/maths/geometry/rotations/conversions/quaternionMatrix/index.htm
		double sqw = (double)qw * (double)qw;
		double sqx = (double)qx * (double)qx;
		double sqy = (double)qy * (double)qy;
		double sqz = (double)qz * (double)qz;
		m00 = (templateType)(sqx - sqy - sqz + sqw); // since sqw + sqx + sqy + sqz =1
		m11 = (templateType)(-sqx + sqy - sqz + sqw);
		m22 = (templateType)(-sqx - sqy + sqz + sqw);

		double tmp1 = (double)qx * (double)qy;
		double tmp2 = (double)qz * (double)qw;
		m10 = (templateType)(2.0 * (tmp1 + tmp2));
		m01 = (templateType)(2.0 * (tmp1 - tmp2));

		tmp1 = (double)qx * (double)qz;
		tmp2 = (double)qy * (double)qw;
		m20 = (templateType)(2.0 * (tmp1 - tmp2));
		m02 = (templateType)(2.0 * (tmp1 + tmp2));
		tmp1 = (double)qy * (double)qz;
		tmp2 = (double)qx * (double)qw;
		m21 = (templateType)(2.0 * (tmp1 + tmp2));
		m12 = (templateType)(2.0 * (tmp1 - tmp2));
	}

	/// @func AppendBitsCouldRealloc
	/// @brief
	/// reallocates (if necessary) in preparation of writing @bits2Append
	/// all internal status will not be changed like @mWritePosBits and so on
	/// @access  public
	/// @notice
	/// It is caller's reponsibility to ensure
	/// @param bits2Append > 0 and @param mReadOnly is false
	/// @author mengdi[Jackie]
	void AppendBitsCouldRealloc(const bit_size_t bits2Append);

	/// @func  WriteBits
	/// @brief  write @bitsCount number of bits into @input
	/// @access      public
	/// @param [in] [const uchar * src] source array
	/// @param [in] [bit_size_t bits2Write] the number of bits to write
	/// @param [in] [bool rightAligned] the alignment of src byte
	/// if true particial bits will be left aligned, otherwise, no shift
	/// @returns void
	/// @remarks
	/// 1.jackie stream internal data are aligned to the left side of byte boundary. so rightAlign should be false
	/// 2.user data are usually aligned to the right side of byte boundary. so rightAlign should be true
	/// @notice
	/// 1.Use true to write user data to jackie stream
	/// 2.Use False to write this jackie stream internal data to another stream
	/// @Author mengdi[Jackie]
	void WriteBits(const uchar* src, bit_size_t bits2Write, bool rightAligned =
		true);

	/// @func Write
	/// @access  public
	/// @brief write an array or raw data in bytes.
	/// NOT do endian swapp.
	/// default is right aligned[true]
	/// @author mengdi[Jackie]
	inline void WriteRaw(const char* src, const byte_size_t bytes2Write) {
		WriteBits((uchar*)src, BYTES_TO_BITS(bytes2Write), true);
	}
	inline void WriteRaw(const uchar* src, const byte_size_t bytes2Write) {
		WriteBits(src, BYTES_TO_BITS(bytes2Write), true);
	}

	/// @brief Write one JackieBits to another.
	/// @param[in] [bits2Write] bits to write
	/// @param[in] [JackieBits] the JackieBits to copy from
	void Write(geco_bit_stream_t *jackieBits, bit_size_t bits2Write);
	inline void Write(geco_bit_stream_t &jackieBits, bit_size_t bits2Write) {
		Write(&jackieBits, bits2Write);
	}
	inline void Write(geco_bit_stream_t *jackieBits) {
		Write(jackieBits, jackieBits->get_payloads());
	}
	inline void Write(geco_bit_stream_t &jackieBits) {
		Write(&jackieBits);
	}

	/// @method WritePtr
	/// @access public
	/// @returns void
	/// @param [in] IntergralType * src pointing to the value to write
	/// @brief
	/// write the dereferenced pointer to any integral type to a bitstream.
	/// Undefine DO_NOT_SWAP_ENDIAN if you need endian swapping.
	template<class IntergralType>
	void WritePtr(IntergralType *src) {
		if (sizeof(IntergralType) == 1)
			WriteBits((uchar*)src, BYTES_TO_BITS(sizeof(IntergralType)), true);
		else {
#ifndef DO_NOT_SWAP_ENDIAN
			if (DoEndianSwap()) {
				uchar output[sizeof(IntergralType)];
				ReverseBytes((uchar*)src, output, sizeof(IntergralType));
				WriteBits((uchar*)output, BYTES_TO_BITS(sizeof(IntergralType)),
					true);
			}
			else
#endif
				WriteBits((uchar*)src, BYTES_TO_BITS(sizeof(IntergralType)),
					true);
		}
	}

	/// @func WriteBitZero
	/// @access  public
	/// @notice @mReadOnly must be false
	/// @author mengdi[Jackie]
	inline void WriteBitZero(void) {
		assert(is_read_only_ == false);

		//AppendBitsCouldRealloc(1);
		//bit_size_t shit = 8 - (mWritingPosBits & 7);
		//data[mWritingPosBits >> 3] = ((data[mWritingPosBits >> 3] >> shit) << shit);
		//mWritingPosBits++;

		AppendBitsCouldRealloc(1);
		/// New bytes need to be zeroed
		if ((writable_bit_pos_ & 7) == 0)
			uchar_data_[writable_bit_pos_ >> 3] = 0;
		writable_bit_pos_++;
	}

	/// @func WriteBitOne
	/// @access  public
	/// @notice @mReadOnly must be false
	/// @author mengdi[Jackie]
	inline void WriteBitOne(void) {
		assert(is_read_only_ == false);
		AppendBitsCouldRealloc(1);

		// Write bit 1
		bit_size_t shift = writable_bit_pos_ & 7;
		shift == 0 ?
			uchar_data_[writable_bit_pos_ >> 3] = 0x80 :
			uchar_data_[writable_bit_pos_ >> 3] |= 0x80 >> shift;
		writable_bit_pos_++;
	}

	/// @func align_writable_bit_pos
	/// @brief align @mWritePosBits to a byte boundary.
	/// @access  public
	/// @notice
	/// this can be used to 'waste' bits to byte align for efficiency reasons It
	/// can also be used to force coalesced bitstreams to start on byte
	/// boundaries so so WriteAlignedBits and ReadAlignedBits both
	/// calculate the same offset when aligning.
	/// @author mengdi[Jackie]
	inline void align_writable_bit_pos(void) {
		writable_bit_pos_ += 8 - (((writable_bit_pos_ - 1) & 7) + 1);
	}

	/// @func write_aligned_bytes
	/// @brief  align the bitstream to the byte boundary and
	/// then write the specified number of bytes.
	/// @access  public
	/// @param [in] [const uchar * src]
	/// @param [in] [const byte_size_t numberOfBytesWrite]
	/// @returns [void]
	/// @notice this is faster than WriteBits() but
	/// wastes the bits to do the alignment for @mWritePosBits and
	/// requires you to call ReadAlignedBits() at the corresponding
	/// read position.
	/// @author mengdi[Jackie]
	void write_aligned_bytes(const uchar *src,
		const byte_size_t numberOfBytesWrite);

	/// @brief Aligns the bitstream, writes inputLength, and writes input.
	/// @access  public
	/// @param[in] inByteArray The data
	/// @param[in] inputLength the size of input.
	/// @param[in] maxBytesWrite max bytes to write
	/// @notice Won't write beyond maxBytesWrite
	void write_aligned_bytes(const uchar *src, const byte_size_t bytes2Write,
		const byte_size_t maxBytes2Write);

	/// @func Write
	/// @brief write a float into 2 bytes, spanning the range,
	/// between @param[floatMin] and @param[floatMax]
	/// @access  public
	/// @param [in] [float src]  value to write into stream
	/// @param [in] [float floatMin] Predetermined mini value of f
	/// @param [in] [float floatMax] Predetermined max value of f
	/// @return bool
	/// @author mengdi[Jackie]
	void write_ranged_float(float src, float floatMin, float floatMax);

	/// @func Write
	/// @brief write any integral type to a bitstream.
	/// @access  public
	/// @param [in] [const templateType & src]
	/// it is user data that is right aligned in default
	/// @return void
	/// @notice will swap endian internally
	/// if DO_NOT_SWAP_ENDIAN not defined
	/// @author mengdi[Jackie]
	template<class IntergralType>
	void Write(const IntergralType &src) {
		if (sizeof(IntergralType) == 1) {
			WriteBits((uchar*)&src, BYTES_TO_BITS(sizeof(IntergralType)));
		}
		else {
#ifndef DO_NOT_SWAP_ENDIAN
			if (DoEndianSwap()) {
				uchar output[sizeof(IntergralType)];
				ReverseBytes((uchar*)&src, output, sizeof(IntergralType));
				WriteBits(output, BYTES_TO_BITS(sizeof(IntergralType)));
			}
			else
#endif
				WriteBits((uchar*)&src, BYTES_TO_BITS(sizeof(IntergralType)));
		}
	}

	/// @func Write
	/// @access  public
	/// @brief Write a bool to a bitstream.
	/// @param [in] [const bool & src] The value to write
	/// @return [bool] true succeed, false failed
	/// @author mengdi[Jackie]
	inline void Write(const bool &src) {
		if (src == true)
			WriteBitOne();
		else
			WriteBitZero();
	}

	inline void Write(const float &src) {
		//int v = FloatToBits(fabs(src));
		int v = FloatToBits(src);
		Write(v);
	}

	/// TODO MOVE THIS into network_address_t by operator <<
	/// @func Write
	/// @brief write a NetworkAddress to stream
	/// @access  public
	/// @param [in] [const NetworkAddress & src]
	/// @return [bool]  true succeed, false failed
	/// @remark
	/// @notice  will not endian swap the address or port
	/// @author mengdi[Jackie]
	//        inline void Write(const network_address_t &src)
	//        {
	//            uchar version = src.GetIPVersion();
	//            Write(version);
	//
	//            if (version == 4)
	//            {
	//                /// Hide the address so routers don't modify it
	//                network_address_t addr = src;
	//                uint binaryAddress = ~src.address.addr4.sin_addr.s_addr;
	//                ushort p = addr.GetPortNetworkOrder();
	//                // Don't endian swap the address or port
	//                WriteBits((uchar*) &binaryAddress,
	//                        BYTES_TO_BITS(sizeof(binaryAddress)), true);
	//                WriteBits((uchar*) &p, BYTES_TO_BITS(sizeof(p)), true);
	//            }
	//            else
	//            {
	//#if NET_SUPPORT_IPV6 == 1
	//                // Don't endian swap
	//                WriteBits((uchar*)&src.address.addr6,
	//                        BYTES_TO_BITS(sizeof(src.address.addr6)), true);
	//#endif
	//            }
	//        }

	/// @func Write
	/// @brief write three bytes into stream
	/// @access  public
	/// @param [in] [const uint24_t & inTemplateVar]
	/// @return [void]  true succeed, false failed
	/// @remark
	/// @notice will align write-position to byte-boundary internally
	/// @see  align_writable_bit_pos()
	/// @author mengdi[Jackie]

	inline void Write(const uint24_t &inTemplateVar) {
		if (!IsBigEndian()) {
			WriteBits((uchar *)&inTemplateVar.val, 24, false);
		}
		else {
			ReverseBytes((uchar *)&inTemplateVar.val, 3);
			WriteBits((uchar *)&inTemplateVar.val, 24, false);
		}
	}

	/// TODO MOVE THIS into guid_t by operator <<
	/// @func Write
	/// @access  public
	/// @param [in] [const JackieGUID & inTemplateVar]
	/// @return void
	/// @author mengdi[Jackie]
	//        inline void Write(const guid_t &inTemplateVar)
	//        {
	//            Write(inTemplateVar.g);
	//        }
	//

	//inline void WriteFrom(const RakWString &src)
	//{
	//  src.serialize(this);
	//}

	inline void Write(const std::string &src, uchar language_id = 0,
		bool write_language_id = false) {
		if (write_language_id)
			WriteMini((uchar*)&language_id, sizeof(uchar) << 3, true);
		geco_string_compressor_t::Instance()->EncodeString(src, 0xFFFF, this,
			write_language_id);
	}
	inline void Write(const char* inStringVar, uchar language_id = 0,
		bool write_language_id = false) {
		if (write_language_id)
			WriteMini((uchar*)&language_id, sizeof(uchar) << 3, true);
		geco_string_compressor_t::Instance()->EncodeString(inStringVar, 0xFFFF,
			this, write_language_id);
	}

	inline void Write(const wchar_t * const &inStringVar) {
		//JackieWString::serialize(inStringVar, this);
	}
	inline void Write(const uchar *src) {
		Write((const char*)src);
	}
	inline void Write(char * const &src) {
		Write((const char*)src);
	}
	inline void Write(uchar * const &src) {
		Write((const char*)src);
	}

	/// @func WriteChanged
	/// @brief write any changed integral type to a bitstream.
	/// @access  public
	/// @param [in] const templateType & latestVal
	/// @param [in] const templateType & lastVal
	/// @return void
	/// @notice
	/// If the current value is different from the last value
	/// the current value will be written.  Otherwise, a single bit will be written
	/// @author mengdi[Jackie]
	template<class templateType>
	inline void WriteChangedValue(const templateType &latestVal,
		const templateType &lastVal) {
		if (latestVal == lastVal) {
			Write(false);
		}
		else {
			Write(true);
			Write(latestVal);
		}
	}

	/// @brief WriteDelta when you don't know what the last value is, or there is no last value.
	/// @param[in] currentValue The current value to write
	/// @func WriteChanged
	/// @brief
	/// writeDelta when you don't know what the last value is, or there is no last value.
	/// @access  public
	/// @param [in] const templateType & currentValue
	/// @return void
	/// @author mengdi[Jackie]
	template<class templateType>
	inline void WriteChangedValue(const templateType &currentValue) {
		Write(true);
		Write(currentValue);
	}

	/// @func WriteMiniChanged
	/// @brief write any integral type to a bitstream.
	/// @access  public
	/// @param [in] const templateType & currVal
	/// The current value to write
	/// @param [in] const templateType & lastValue
	///  The last value to compare against
	/// @return void
	/// @notice
	/// If the current value is different from the last value. the current
	/// value will be written.  Otherwise, a single bit will be written
	/// For floating point, this is lossy, using 2 bytes for a float and
	/// 4 for a double. The range must be between -1 and +1.
	/// For non-floating point, this is lossless, but only has benefit
	/// if you use less than half the bits of the type
	/// If you are not using DO_NOT_SWAP_ENDIAN the opposite is
	/// true for types larger than 1 byte
	/// @author mengdi[Jackie]
	template<class templateType>
	inline void WriteMiniChanged(const templateType&currVal,
		const templateType &lastValue) {
		if (currVal == lastValue) {
			Write(false);
		}
		else {
			Write(true);
			WriteMini(currVal);
		}
	}

	/// @brief Write a bool delta.  Same thing as just calling Write
	/// @param[in] currentValue The current value to write
	/// @param[in] lastValue The last value to compare against

	inline void WriteMiniChanged(const bool &currentValue,
		const bool& lastValue) {
		(void)lastValue;
		Write(currentValue);
	}

	/// @brief Same as WriteMiniChanged()
	/// when we have an unknown second parameter
	template<class templateType>
	inline void WriteMiniChanged(const templateType &currentValue) {
		Write(true);
		WriteMini(currentValue);
	}

	/// @func WriteMini
	/// @access  public
	/// @param [in] const uchar * src
	/// @param [in] const bit_size_t bits2Write  write size in bits
	/// @param [in] const bool isUnsigned
	/// @return void
	/// @notice
	/// this function assumes that @src points to a native type,
	/// compress and write it.
	/// @Remarks
	/// assume we have src with value of FourOnes-FourOnes-FourOnes-11110001
	///++++++++++++++> High Memory Address (hma)
	///++++++++++++++++++++++++++++++
	/// | FourOnes | FourOnes | FourOnes | 11110001 |  Big Endian
	///++++++++++++++++++++++++++++++
	///++++++++++++++++++++++++++++++
	/// |11110001 | FourOnes | FourOnes | FourOnes |  Little Endian
	///++++++++++++++++++++++++++++++
	/// for little endian, the high bytes are located in hma and so @currByte should
	/// increment from value of highest index ((bits2Write >> 3) - 1)
	/// for big endian, the high bytes are located in lma and so @currByte should
	/// increment from value of lowest index (0)
	/// 在字节内部，一个字节的二进制排序，不存在大小端问题。
	/// 就和平常书写的一样，先写高位，即低地址存储高位。
	/// 如char a=0x12.存储从低位到高位就为0001 0010
	/// @author mengdi[Jackie]
	void WriteMini(const uchar* src, const bit_size_t bits2Write,
		const bool isUnsigned);

	/// @func WriteMini
	/// @brief Write any integral type to a bitstream,
	/// endian swapping counters internally. default is unsigned (isUnsigned = true)
	/// @access  public
	/// @param [in] const IntergralType & src
	/// @return void
	/// @notice
	/// For floating point, this is lossy, using 2 bytes for a float and 4 for
	/// a double.  The range must be between -1 and +1.
	/// For non-floating point, this is lossless, but only has benefit
	/// if you use less than half the bits of the type
	/// we write low bits and reassenble the value in receiver endpoint
	/// based on its endian, so no need to do endian swap here
	/// @author mengdi[Jackie]
	template<class IntergralType>
	inline void WriteMini(const IntergralType &src, bool isUnsigned = true) {
		WriteMini((uchar*)&src, sizeof(IntergralType) << 3, isUnsigned);
	}

	/// move this to network_address_t by operator <<
	//        inline void WriteMini(const network_address_t &src)
	//        {
	//            //Write(src);
	//            uchar version = src.GetIPVersion();
	//            WriteMini(version);
	//
	//            if (version == 4)
	//            {
	//                /// Hide the address so routers don't modify it
	//                network_address_t addr = src;
	//                uint binaryAddress = ~src.address.addr4.sin_addr.s_addr;
	//                ushort p = addr.GetPortNetworkOrder();
	//                WriteMini(binaryAddress);
	//                WriteMini(p);
	//            }
	//            else
	//            {
	//#if NET_SUPPORT_IPV6 == 1
	//                uint binaryAddress = src.address.addr6;
	//                WriteMini(binaryAddress);
	//#endif
	//            }
	//        }
	//        inline void WriteMini(const guid_t &src)
	//        {
	//            WriteMini(src.g);
	//        }
	inline void WriteMini(const uint24_t &var) {
		WriteMini(var.val);
	}
	inline void WriteMini(const bool &src) {
		Write(src);
	}

	/// @access public
	/// @returns void
	template<class destType, class srcType>
	void WriteCasted(const srcType &value) {
		destType val = (destType)value;
		Write(val);
	}

	/// @method WriteBitsIntegerRange
	/// @access public
	/// @returns void
	/// @param [in] const templateType value
	/// value Integer value to write, which should be
	/// between @param mini and @param max
	/// @param [in] const templateType mini
	/// @param [in] const templateType max
	/// @param [in] bool allowOutsideRange
	/// If true, all sends will take an extra bit,
	/// however value can deviate from outside @a minimum and @a maximum.
	/// If false, will assert if the value deviates.
	/// This should match the corresponding value passed to Read().
	/// @brief
	/// given the minimum and maximum values for an integer type,
	/// figure out the minimum number of bits to represent the range
	/// Then write only those bits
	/// @notice
	/// a static is used so that the required number of bits for
	/// (maximum-minimum pair) is only calculated once.
	/// This does require that @param mini and @param max are fixed
	/// values for a given line of code for the life of the program
	/// @see
	template<class IntegerType> void write_ranged_integer(
		const IntegerType value, const IntegerType mini,
		const IntegerType max, bool allowOutsideRange = false) {
		IntegerType diff = max - mini;
		int requiredBits = BYTES_TO_BITS(sizeof(IntegerType))
			- get_leading_zeros_size(diff);
		write_ranged_integer(value, mini, max, requiredBits, allowOutsideRange);
	}

	/// @brief
	/// only work for positive integers but you can transfer nagative integers as postive
	/// integers and transform it back to negative at receipt endpoint.
	/// the smaller difference between min and max, the less bits used to transmit
	/// eg. given a number of 105 in 100 - 120 is more efficiently compressed
	/// than that in 0 - 120, you actually is sending number of 105-100=5
	/// it is even more efficient than using WriteMini()
	/// @Remarks
	/// Assume@valueBeyondMini's value is 00000000 - 00101100
	/// Memory Address ------------------>
	/// 00000000   00101100   Big Endian
	/// 00101100   00000000   Little Endian
	/// so for big endian, we need to reverse byte so that
	/// the high byte of 00101100 that was put in low address can be written correctly
	/// for little endian, we do nothing.
	template<class IntegerType>
	void write_ranged_integer(const IntegerType value, const IntegerType mini,
		const IntegerType max, const int requiredBits,
		bool allowOutsideRange = false) {
		assert(max >= mini);
		assert(allowOutsideRange == true || (value >= mini && value <= max));

		if (allowOutsideRange) {
			if (value < mini || value > max)  ///< out of range
			{
				Write(true);
				WriteMini(value);
				return;
			}
			Write(false);  ///< inside range
		}

		IntegerType valueBeyondMini = value - mini;
		if (IsBigEndian()) {
			uchar output[sizeof(IntegerType)];
			ReverseBytes((uchar*)&valueBeyondMini, output,
				sizeof(IntegerType));
			WriteBits(output, requiredBits, true);
		}
		else {
			WriteBits((uchar*)&valueBeyondMini, requiredBits, true);
		}
	}

	/// @method write_normal_vector
	/// @access public
	/// @returns void
	/// @param [in] templateType x
	/// @param [in] templateType y
	/// @param [in] templateType z
	/// @brief
	/// Write a normalized 3D vector, using (at most) 4 bytes + 3 bits
	/// instead of 12 - 24 bytes. Accurate to 1/32767.5.
	/// @notice
	/// Will further compress y or z axis aligned vectors.
	/// templateType for this function must be a float or double
	/// @see
	template<class templateType> void write_normal_vector(templateType x,
		templateType y) {
		assert(x <= 1.01 && y <= 1.01 && x >= -1.01 && y >= -1.01);
		write_ranged_float((float)x, -1.0f, 1.0f);
		write_ranged_float((float)y, -1.0f, 1.0f);
	}
	template<class templateType> void write_normal_vector(templateType x,
		templateType y, templateType z) {
		assert(
			x <= 1.01 && y <= 1.01 && z <= 1.01 && x >= -1.01 && y >= -1.01
			&& z >= -1.01);
		write_ranged_float((float)x, -1.0f, 1.0f);
		write_ranged_float((float)y, -1.0f, 1.0f);
		write_ranged_float((float)z, -1.0f, 1.0f);
	}

	/// @method write_vector
	/// @access public
	/// @returns void
	/// @brief Write a vector, using 10 bytes instead of 12.
	/// @notice
	/// Loses accuracy to about 3/10ths and only saves 2 bytes,
	/// so only use if accuracy is not important
	/// templateType for this function must be a float or double
	/// @see
	template<class templateType> void write_vector(templateType x,
		templateType y) {
		templateType magnitude = sqrt(x * x + y * y);
		Write((float)magnitude);
		if (magnitude > 0.00001f) {
			WriteMini((float)(x / magnitude));
			WriteMini((float)(y / magnitude));
		}
	}
	template<class templateType> void write_vector(templateType x,
		templateType y, templateType z) {
		templateType magnitude = sqrt(x * x + y * y + z * z);
		Write((float)magnitude);
		if (magnitude > 0.00001f) {
			WriteMini((float)(x / magnitude));
			WriteMini((float)(y / magnitude));
			WriteMini((float)(z / magnitude));
		}
	}

	/// @method write_normal_quat
	/// @access public
	/// @returns void
	/// @brief
	/// Write a normalized quaternion in (18 bits[best case] to 6 bytes[worest case]) + 4 bits instead of 16 bytes.
	/// Slightly lossy.
	/// @notice
	/// templateType for this function must be a float or double
	/// @see
	template<class templateType> void write_normal_quat(templateType w,
		templateType x, templateType y, templateType z) {
		Write((bool)(w < 0.0));
		Write((bool)(x < 0.0));
		Write((bool)(y < 0.0));
		Write((bool)(z < 0.0));
		WriteMini((ushort)(fabs(x) * 65535.0));
		WriteMini((ushort)(fabs(y) * 65535.0));
		WriteMini((ushort)(fabs(z) * 65535.0));
		// Leave out w and calculate it on the target
	}

	/// @method write_orth_matrix
	/// @access public
	/// @returns void
	/// @brief
	/// Write an orthogonal matrix by creating a quaternion,
	/// and writing 3 components of the quaternion in 2 bytes each.
	/// @notice
	/// Lossy, although the result is renormalized
	/// Use (18 bits to 6 bytes) +4 bits instead of 36
	/// templateType for this function must be a float or double
	/// @see write_normal_quat()
	template<class templateType> void write_orth_matrix(templateType m00,
		templateType m01, templateType m02, templateType m10,
		templateType m11, templateType m12, templateType m20,
		templateType m21, templateType m22) {
		double qw;
		double qx;
		double qy;
		double qz;

		// Convert matrix to quat
		// http://www.euclideanspace.com/maths/geometry/rotations/conversions/matrixQuaternion/
		float sum;
		sum = 1 + m00 + m11 + m22;
		if (sum < 0.0f)
			sum = 0.0f;
		qw = sqrt(sum) / 2;
		sum = 1 + m00 - m11 - m22;
		if (sum < 0.0f)
			sum = 0.0f;
		qx = sqrt(sum) / 2;
		sum = 1 - m00 + m11 - m22;
		if (sum < 0.0f)
			sum = 0.0f;
		qy = sqrt(sum) / 2;
		sum = 1 - m00 - m11 + m22;
		if (sum < 0.0f)
			sum = 0.0f;
		qz = sqrt(sum) / 2;
		if (qw < 0.0)
			qw = 0.0;
		if (qx < 0.0)
			qx = 0.0;
		if (qy < 0.0)
			qy = 0.0;
		if (qz < 0.0)
			qz = 0.0;
		qx = _copysign((double)qx, (double)(m21 - m12));
		qy = _copysign((double)qy, (double)(m02 - m20));
		qz = _copysign((double)qz, (double)(m10 - m01));

		write_normal_quat(qw, qx, qy, qz);
	}

	/// @brief  Write zeros until the bitstream is filled up to @param bytes
	/// @notice will internally align write pos and then reallocate if necessary
	///  the @mWritePosBits will be byte aligned
	void pad_zeros_up_to(uint bytes);

	/// @brief swao bytes starting from @data with offset given
	inline void swap_bytes(uint byteOffset, uint length) {
		if (DoEndianSwap())
			ReverseBytes(uchar_data_ + byteOffset, length);
	}
	inline byte_size_t get_bytes_length() {
		return BITS_TO_BYTES(writable_bit_pos_);
	}
	/// @brief Makes a copy of the internal data for you @param _data
	/// will point to the stream. Partial bytes are left aligned.
	/// @param[out] _data The allocated copy of GetData().
	/// @return The length in bytes of remaining bytes between start_offset and BITS_TO_BYTES(writable_bit_pos_)
	/// @pre _data points to valid and enough memory space.
	/// caller may need use get_bytes_length() to get the
	/// length of data in the stream
	/// @note all bytes are copied besides the bytes in get_payloads().
	inline bit_size_t copy_data(uchar* dest, byte_size_t size2copy,
		byte_size_t start_offset = 0) {
		assert(writable_bit_pos_ > 0);
		assert(BITS_TO_BYTES(writable_bit_pos_) >= (size2copy + start_offset));
		// we leave memory allocation to caller which is more flexable
		if (size2copy == 0)
			size2copy = get_bytes_length();
		memcpy(dest, uchar_data_ + start_offset, sizeof(uchar) * size2copy);
		return BITS_TO_BYTES(writable_bit_pos_) - start_offset;
	}
	/// @brief Makes a copy of the internal data for you @param _data
	/// will point to the stream. Partial bytes are left aligned
	/// @param[out] _data The allocated copy of GetData()
	/// @return The length in bits of the stream.
	/// @notice
	/// all bytes are copied besides the bytes in GetPayLoadBits()
	bit_size_t copy(uchar*& _data, bool allocmem = true) const {
		assert(writable_bit_pos_ > 0);
		if (allocmem)
			_data = (uchar*)geco_malloc_ext(BITS_TO_BYTES(writable_bit_pos_),
				FILE_AND_LINE);
		memcpy(_data, uchar_data_,
			sizeof(uchar) * BITS_TO_BYTES(writable_bit_pos_));
		return writable_bit_pos_;
	}

	///@brief Ignore data we don't intend to read
	/// @ret the old read pos
	bit_size_t skip_read_bits(const bit_size_t numberOfBits) {
		readable_bit_pos_ += numberOfBits;
		return readable_bit_pos_ - numberOfBits;
	}
	/// when read pos is not in byte bounary, readable_bit_pos_ = 7
	/// if we skip one byte, readable_bit_pos_ = 15, which is still not in 
	/// byte bounary
	byte_size_t skip_read_bytes(const byte_size_t numberOfBytes) {
		return skip_read_bits(BYTES_TO_BITS(numberOfBytes));
	}

	// @pre: writable_bit_pos_ is on the byte boundary
	void write_one_aligned_byte(const char *inByteArray) {
		assert((writable_bit_pos_ & 7) == 0);
		AppendBitsCouldRealloc(8);
		uchar_data_[writable_bit_pos_ >> 3] = inByteArray[0];
		writable_bit_pos_ += 8;
	}

	// @pre: readable_bit_pos_ is on the byte boundary
	void read_one_aligned_byte(char *inOutByteArray) {
		assert((readable_bit_pos_ & 7) == 0);
		assert(get_payloads() >= 8);
		inOutByteArray[0] = uchar_data_[(readable_bit_pos_ >> 3)];
		readable_bit_pos_ += 8;
	}

	void write_two_aligned_bytes(const char *inByteArray) {
		assert((writable_bit_pos_ & 7) == 0);
		AppendBitsCouldRealloc(16);
#ifndef DO_NOT_SWAP_ENDIAN
		if (DoEndianSwap()) {
			uchar_data_[(writable_bit_pos_ >> 3) + 0] = inByteArray[1];
			uchar_data_[(writable_bit_pos_ >> 3) + 1] = inByteArray[0];
		}
		else
#endif
		{
			uchar_data_[(writable_bit_pos_ >> 3) + 0] = inByteArray[0];
			uchar_data_[(writable_bit_pos_ >> 3) + 1] = inByteArray[1];
		}

		writable_bit_pos_ += 16;
	}
	void read_two_aligned_bytes(char *inOutByteArray) {
		assert((readable_bit_pos_ & 7) == 0);
		assert(get_payloads() >= 16);
		//if (mReadPosBits + 16 > mWritePosBits) return ;
#ifndef DO_NOT_SWAP_ENDIAN
		if (DoEndianSwap()) {
			inOutByteArray[0] = uchar_data_[(readable_bit_pos_ >> 3) + 1];
			inOutByteArray[1] = uchar_data_[(readable_bit_pos_ >> 3) + 0];
		}
		else
#endif
		{
			inOutByteArray[0] = uchar_data_[(readable_bit_pos_ >> 3) + 0];
			inOutByteArray[1] = uchar_data_[(readable_bit_pos_ >> 3) + 1];
		}

		readable_bit_pos_ += 16;
	}

	void WriteFourAlignedBytes(const char *inByteArray) {
		assert((writable_bit_pos_ & 7) == 0);
		AppendBitsCouldRealloc(32);
#ifndef DO_NOT_SWAP_ENDIAN
		if (DoEndianSwap()) {
			uchar_data_[(writable_bit_pos_ >> 3) + 0] = inByteArray[3];
			uchar_data_[(writable_bit_pos_ >> 3) + 1] = inByteArray[2];
			uchar_data_[(writable_bit_pos_ >> 3) + 2] = inByteArray[1];
			uchar_data_[(writable_bit_pos_ >> 3) + 3] = inByteArray[0];
		}
		else
#endif
		{
			uchar_data_[(writable_bit_pos_ >> 3) + 0] = inByteArray[0];
			uchar_data_[(writable_bit_pos_ >> 3) + 1] = inByteArray[1];
			uchar_data_[(writable_bit_pos_ >> 3) + 2] = inByteArray[2];
			uchar_data_[(writable_bit_pos_ >> 3) + 3] = inByteArray[3];
		}

		writable_bit_pos_ += 32;
	}
	void ReadFourAlignedBytes(char *inOutByteArray) {
		assert((readable_bit_pos_ & 7) == 0);
		assert(get_payloads() >= 32);
		//if (mReadPosBits + 4 * 8 > mWritePosBits) return;
#ifndef DO_NOT_SWAP_ENDIAN
		if (DoEndianSwap()) {
			inOutByteArray[0] = uchar_data_[(readable_bit_pos_ >> 3) + 3];
			inOutByteArray[1] = uchar_data_[(readable_bit_pos_ >> 3) + 2];
			inOutByteArray[2] = uchar_data_[(readable_bit_pos_ >> 3) + 1];
			inOutByteArray[3] = uchar_data_[(readable_bit_pos_ >> 3) + 0];
		}
		else
#endif
		{
			inOutByteArray[0] = uchar_data_[(readable_bit_pos_ >> 3) + 0];
			inOutByteArray[1] = uchar_data_[(readable_bit_pos_ >> 3) + 1];
			inOutByteArray[2] = uchar_data_[(readable_bit_pos_ >> 3) + 2];
			inOutByteArray[3] = uchar_data_[(readable_bit_pos_ >> 3) + 3];
		}

		readable_bit_pos_ += 32;
	}
	void WriteBitOnes(uint num) {
		assert(num > 0);
		while (num-- > 0) {
			this->WriteBitOne();
		}
	}
	void WriteBitZeros(uint num) {
		assert(num > 0);
		while (num-- > 0) {
			this->WriteBitZero();
		}
	}
	void WriteMini(geco_bit_stream_t& src);
	void ReadMini(geco_bit_stream_t& dest);

	/// @briefAssume we have value of 00101100   00000000   Little Endian
	/// the required bits are 8(0000000)+2(first 2 bits from left to right in 00101100)
	/// = 10 buts in total
	static int get_leading_zeros_size(char x) {
		return get_leading_zeros_size((uchar)x);
	}
	static int get_leading_zeros_size(uchar x) {
		uchar y;
		int n;

		n = 8;
		y = x >> 4;
		if (y != 0) {
			n = n - 4;
			x = y;
		}
		y = x >> 2;
		if (y != 0) {
			n = n - 2;
			x = y;
		}
		y = x >> 1;
		if (y != 0)
			return n - 2;
		return (int)(n - x);
	}
	static int get_leading_zeros_size(short x) {
		return get_leading_zeros_size((ushort)x);
	}
	static int get_leading_zeros_size(ushort x) {
		ushort y;
		int n;

		n = 16;
		y = x >> 8;
		if (y != 0) {
			n = n - 8;
			x = y;
		}
		y = x >> 4;
		if (y != 0) {
			n = n - 4;
			x = y;
		}
		y = x >> 2;
		if (y != 0) {
			n = n - 2;
			x = y;
		}
		y = x >> 1;
		if (y != 0)
			return n - 2;
		return (int)(n - x);
	}
	static int get_leading_zeros_size(int x) {
		return get_leading_zeros_size((uint)x);
	}
	static int get_leading_zeros_size(uint x) {
		uint y;
		int n;

		n = 32;
		y = x >> 16;
		if (y != 0) {
			n = n - 16;
			x = y;
		}
		y = x >> 8;
		if (y != 0) {
			n = n - 8;
			x = y;
		}
		y = x >> 4;
		if (y != 0) {
			n = n - 4;
			x = y;
		}
		y = x >> 2;
		if (y != 0) {
			n = n - 2;
			x = y;
		}
		y = x >> 1;
		if (y != 0)
			return n - 2;
		return (int)(n - x);
	}
	static int get_leading_zeros_size(int64 x) {
		return get_leading_zeros_size((uint64)x);
	}
	static int get_leading_zeros_size(uint64 x) {
		uint64 y;
		int n;

		n = 64;
		y = x >> 32;
		if (y != 0) {
			n = n - 32;
			x = y;
		}
		y = x >> 16;
		if (y != 0) {
			n = n - 16;
			x = y;
		}
		y = x >> 8;
		if (y != 0) {
			n = n - 8;
			x = y;
		}
		y = x >> 4;
		if (y != 0) {
			n = n - 4;
			x = y;
		}
		y = x >> 2;
		if (y != 0) {
			n = n - 2;
			x = y;
		}
		y = x >> 1;
		if (y != 0)
			return n - 2;
		return (int)(n - x);
	}

	inline static bool DoEndianSwap(void) {
#ifndef DO_NOT_SWAP_ENDIAN
		return IsNetworkOrder() == false;
#else
		return false;
#endif
	}
	inline static bool IsNetworkOrder(void) {
		static int a = 0x01;
		static bool isNetworkOrder = *((char*)&a) != 1;
		return isNetworkOrder;
	}
	inline static bool IsBigEndian(void) {
		return IsNetworkOrder();
	}

	/// @Brief faster than ReverseBytes() if you want to reverse byte
	/// for a variable teself internnaly like uint64_t will loop 12 times
	/// compared to 8 times using ReverseBytes()
	inline static void ReverseBytes(uchar *src, const uint length) {
		uchar temp;
		for (uint i = 0; i < (length >> 1); i++) {
			temp = src[i];
			src[i] = src[length - i - 1];
			src[length - i - 1] = temp;
		}
	}
	inline static void ReverseBytes(uchar *src, uchar *dest,
		const uint length) {
		for (uint i = 0; i < length; i++) {
			dest[i] = src[length - i - 1];
		}
	}

	static int FloatToBits(float f, int exponentBits = 8,
		int mantissaBits = 23);
	static float BitsToFloat(int i, int exponentBits = 8,
		int mantissaBits = 23);

	/// Can only print 4096 size of uchar no materr is is bit or byte
	/// mainly used for dump binary data
	static void Bitify(char* out, int mWritePosBits, unsigned char* mBuffer,
		bool hide_zero_low_bytes = false);
	void Bitify(bool hide_zero_low_bytes = false);
	static void Hexlify(char* outstr, bit_size_t bitsPrint, uchar* src);
	void Hexlify(void);
	};

#endif /* SRC_COMMON_DS_GECO_BIT_STREAM_H_ */
