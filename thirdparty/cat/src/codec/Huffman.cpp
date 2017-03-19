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

#include <cat/codec/Huffman.hpp>
using namespace std;
using namespace cat;

static void WriteSymbol(string &str, u32 bits, u32 count)
{
	for (u32 ii = 0; ii < count; ++ii)
	{
		str += ((bits & (1 << ii)) ? '1' : '0');
	}
}

static void BackoutSymbol(string &str, u32 count)
{
	str = str.substr(0, str.length() - count);
}

static u32 ReadBits(string &str, u32 count)
{
	u32 n = 0;

	for (u32 ii = 0; ii < count; ++ii)
	{
		if (str.at(ii) == '1')
			n |= 1 << ii;
	}

	str = str.substr(count, str.length() - count);

	return n;
}

void HuffmanTree::Kill(HuffmanTreeNode *node)
{
	if (!node) return;

	for (u32 ii = 0; ii < _code_symbols; ++ii)
		Kill(node->children[ii]);

	delete node;
}

void HuffmanTree::FillEncodings(HuffmanTreeNode *node, string &encoding)
{
	if (!node) return;

	node->encoding = encoding;

	bool leaf = true;

	for (u32 ii = 0; ii < _code_symbols; ++ii)
	{
		HuffmanTreeNode *child = node->children[ii];

		if (child)
		{
			WriteSymbol(encoding, ii, _code_symbol_bits);

			FillEncodings(child, encoding);

			BackoutSymbol(encoding, _code_symbol_bits);

			leaf = false;
		}
	}

	if (leaf)
	{
		CAT_WARN("HuffmanTree") << node->letter << " = " << encoding;
	}
}

HuffmanTree::HuffmanTree()
{
}

void HuffmanTree::Initialize(u32 code_symbols, HuffmanTreeNode *root)
{
	_code_symbols = code_symbols;
	_code_symbol_bits = BSR32(code_symbols - 1) + 1;

	_root = root;

	string empty_bs;
	FillEncodings(root, empty_bs);
}

HuffmanTree::~HuffmanTree()
{
	Kill(_root);
}

double HuffmanTree::ExpectedLength()
{
	double sum = 0, prob_sum = 0;

	for (Map::iterator ii = _encoding_map.begin(); ii != _encoding_map.end(); ++ii)
	{
		HuffmanTreeNode *node = ii->second;

		prob_sum += node->probability;
		sum += node->probability * node->encoding.length();
	}

	return sum / prob_sum;
}

bool HuffmanTree::Encode(const u8 *data, u32 bytes, string &bs)
{
	for (u32 ii = 0; ii < bytes; ++ii)
	{
		u32 letter = data[ii];

		HuffmanTreeNode *node = _encoding_map[letter];
		if (!node) return false;

		bs += node->encoding;
	}

	return true;
}

u32 HuffmanTree::Decode(string bs, u8 *data, u32 max_bytes)
{
	HuffmanTreeNode *node = _root;
	u32 ii = 0;

	// While there are more bits to read,
	while (bs.length() > 0)
	{
		u32 bits = ReadBits(bs, _code_symbol_bits);

		HuffmanTreeNode *next = node->children[bits];

		// If at the end of the tree,
		if (!next)
		{
			// If out of space,
			if (ii >= max_bytes)
			{
				return 0;
			}

			// Write out symbol
			data[ii++] = (u8)node->letter;

			// Reset to root and keep reading
			node = _root;
		}
		else
		{
			// Else- Traverse the tree down towards our target
			node = next;
		}
	}

	// Fail if the bit stream did not end on a symbol
	if (node != _root)
	{
		return 0;
	}

	return ii;
}

HuffmanTreeFactory::HuffmanTreeFactory()
{
	_tree = 0;
}

HuffmanTreeFactory::~HuffmanTreeFactory()
{
	if (_tree)
	{
		for (HuffmanTree::Map::iterator ii = _tree->_encoding_map.begin(); ii != _tree->_encoding_map.end(); ++ii)
		{
			HuffmanTreeNode *node = ii->second;
			delete node;
		}

		delete _tree;
	}
}

bool HuffmanTreeFactory::AddSymbol(u32 letter, ProbabilityType probability)
{
	if (_tree)
	{
		// If already added,
		if (_tree->_encoding_map.find(letter) != _tree->_encoding_map.end())
			return false;
	}
	else
	{
		_tree = new HuffmanTree;
		if (!_tree) return false;
	}

	HuffmanTreeNode *node = new HuffmanTreeNode;
	if (!node) return false;

	node->letter = letter;
	node->probability = probability;
	CAT_OBJCLR(node->children);

	_tree->_encoding_map[letter] = node;
	_heap.push(node);

	return true;
}

HuffmanTree *HuffmanTreeFactory::BuildTree(u32 code_symbols)
{
	if (_heap.size() < 1) return 0;

	while (_heap.size() > 1)
	{
		HuffmanTreeNode *branch = new HuffmanTreeNode;

		CAT_OBJCLR(*branch);
		ProbabilityType probability_sum = 0.;

		// For each code symbol,
		for (u32 ii = 0; ii < code_symbols; ++ii)
		{
			HuffmanTreeNode *leaf = _heap.top();
			_heap.pop();

			branch->children[ii] = leaf;
			probability_sum += leaf->probability;

			if (_heap.empty())
				break;
		}

		branch->probability = probability_sum;

		// Push the combined branch back on the heap
		_heap.push(branch);
	}

	HuffmanTreeNode *root = _heap.top();
	_heap.pop();

	HuffmanTree *tree = _tree;
	tree->Initialize(code_symbols, root);
	_tree = 0;

	return tree;
}
