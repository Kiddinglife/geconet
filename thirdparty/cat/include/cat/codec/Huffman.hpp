/*
	Copyright (c) 2011 Christopher A. Taylor.  All rights reserved.

	Redistribution and use in source and binary forms, with or without
	modification, are permitted provided that the following conditions are met:

	* Redistributions of source code must retain the above copyright notice,
	  this list of conditions and the following disclaimer.
	* Redistributions in binary form must reproduce the above copyright notice,
	  this list of conditions and the following disclaimer in the documentation
	  and/or other materials provided with the distribution.
	* Neither the name of LibCat nor the names of its contributors may be used
	  to endorse or promote products derived from this software without
	  specific prior written permission.

	THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
	AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
	IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
	ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
	LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
	CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
	SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
	INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
	CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
	ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
	POSSIBILITY OF SUCH DAMAGE.
*/

// This is for MATH-4280 Information Theory homework at Georgia Tech,
// so this is a little different from practical usage.  For the netcode stuff
// I am thinking about incorporating LZMA compression for the packets

// TODO: Optimize out the STL classes and specialize for byte streams with binary encoding

#ifndef CAT_CODEC_HUFFMAN_HPP
#define CAT_CODEC_HUFFMAN_HPP

#include <cat/math/BitMath.hpp>

#include <cmath>
#include <map>
#include <queue>
#include <functional>
#include <string>

namespace cat {


typedef double ProbabilityType;

// Uses STL log10() to compute the base-2 logarithm of a double
CAT_INLINE double log2(double x)
{
	return std::log10((double)(x)) / std::log10(2.);
}


// One letter in an alphabet with a probability and its position in a tree
struct HuffmanTreeNode
{
	static const u32 MAX_CODE_SYMBOLS = 16;

	u32 letter;
	ProbabilityType probability;

	// Encoding
	std::string encoding;

	HuffmanTreeNode *children[MAX_CODE_SYMBOLS];

	struct HeapGreater
	{
		CAT_INLINE bool operator()(const HuffmanTreeNode *lhs, const HuffmanTreeNode *rhs)
		{
			return lhs->probability > rhs->probability;
		}
	};
};


// Helper class that provides utilities for operating on HuffmanTreeNode objects
class HuffmanTree
{
	friend class HuffmanTreeFactory;

	typedef std::map<u32, HuffmanTreeNode*> Map;

	// Number of symbols in the encoded form (usually 2 for binary encoding)
	u32 _code_symbols;

	// Number of bits per encoded symbol (usually 1 for binary encoding)
	u32 _code_symbol_bits;

	HuffmanTreeNode *_root;
	Map _encoding_map;

	// Recursively free memory for a Huffman tree
	void Kill(HuffmanTreeNode *node);

	// Fill in encodings for the whole tree
	void FillEncodings(HuffmanTreeNode *node, std::string &encoding);

	// Hidden constructor so only the factory can create these
	HuffmanTree();

	// Initialization function for the factory
	void Initialize(u32 code_symbols, HuffmanTreeNode *root);

public:
	// Free memory for the dynamically allocated nodes in the tree
	~HuffmanTree();

	double ExpectedLength();

	// Encode a string of letters
	bool Encode(const u8 *data, u32 bytes, std::string &bs);

	// Decode to a string of letters
	// Returns number of bytes decoded
	u32 Decode(std::string bs, u8 *data, u32 max_bytes);
};


// Object that builds canonical form Huffman trees for compression
class HuffmanTreeFactory
{
	typedef std::priority_queue<HuffmanTreeNode*, std::vector<HuffmanTreeNode*>, HuffmanTreeNode::HeapGreater > Heap;

	// Proto-tree nodes stored in a heap
	Heap _heap;

	// Preallocates proto-tree object for the map so it doesn't need to copy the map around
	HuffmanTree *_tree;

public:
	HuffmanTreeFactory();

	// Free memory for the dynamically allocated nodes in the heap
	~HuffmanTreeFactory();

	// Add a symbol to the proto-tree
	bool AddSymbol(u32 letter, ProbabilityType probability);

	// Build a tree from the added symbols, clearing the proto-tree
	HuffmanTree *BuildTree(u32 code_symbols);
};


} // namespace cat

#endif // CAT_CODEC_HUFFMAN_HPP
