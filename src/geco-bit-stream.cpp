/*
 * geco-bit-stream.cpp
 *
 *  Created on: 15Jul.,2016
 *      Author: jackiez
 */

#include "geco-bit-stream.h"

#include <list>
#include <algorithm>
GECO_STATIC_FACTORY_DEFIS(geco_bit_stream_t, geco_bit_stream_t);

const unsigned int englishCharacterFrequencies[256] = { 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 722, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 11084, 58, 63, 1, 0, 31, 0, 317, 64, 64, 44, 0, 695, 62, 980, 266,
        69, 67, 56, 7, 73, 3, 14, 2, 69, 1, 167, 9, 1, 2, 25, 94, 0, 195, 139,
        34, 96, 48, 103, 56, 125, 653, 21, 5, 23, 64, 85, 44, 34, 7, 92, 76,
        147, 12, 14, 57, 15, 39, 15, 1, 1, 1, 2, 3, 0, 3611, 845, 1077, 1884,
        5870, 841, 1057, 2501, 3212, 164, 531, 2019, 1330, 3056, 4037, 848, 47,
        2586, 2919, 4771, 1707, 535, 1106, 152, 1243, 100, 0, 2, 0, 10, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0 };
/// HuffmanEncodingTree implementations
HuffmanEncodingTree::HuffmanEncodingTree() {
    root = 0;
}
HuffmanEncodingTree::~HuffmanEncodingTree() {
    FreeMemory();
}
void HuffmanEncodingTree::FreeMemory(void) {
    if (root == 0)
        return;

    // Use an in-order traversal to delete the tree
    std::list<HuffmanEncodingTreeNode *> nodeQueue;
    HuffmanEncodingTreeNode *node;
    nodeQueue.push_back(root);

    while (nodeQueue.size() > 0) {
        node = nodeQueue.front();
        nodeQueue.pop_front();

        if (node->left)
            nodeQueue.push_back(node->left);

        if (node->right)
            nodeQueue.push_back(node->right);

        geco_delete(node, FILE_AND_LINE);
    }

    // Delete the encoding table
    for (int i = 0; i < 256; i++)
        geco_free_ext(encodingTable[i].encoding, FILE_AND_LINE);

    root = 0;
}
// Given a frequency table of 256 elements, all with a frequency of 1 or more, generate the tree
static inline bool cmp_node_weight(const HuffmanEncodingTreeNode* t1,
    const HuffmanEncodingTreeNode* t2) {
    return t1->weight < t2->weight;
}
static inline bool cmp_char_encoding_bitslen(CharacterEncoding* t1,
    CharacterEncoding* t2) {
    return t1->bitLength < t2->bitLength;
}
void HuffmanEncodingTree::GenerateFromFrequencyTable(
    const unsigned int frequencyTable[256]) {
    if (frequencyTable == NULL)
        frequencyTable = englishCharacterFrequencies;
    int counter;
    HuffmanEncodingTreeNode * node;
    HuffmanEncodingTreeNode *leafList[256]; // Keep a copy of the pointers to all the leaves so we can generate the encryption table bottom-up, which is easier

// 1.  Make 256 tree nodes each with a weight equal to the frequency of the corresponding character
    std::list<HuffmanEncodingTreeNode *> huffmanEncodingTreeNodeList;

    FreeMemory();

    for (counter = 0; counter < 256; counter++) {
        node = geco_new<HuffmanEncodingTreeNode>(FILE_AND_LINE);
        node->left = 0;
        node->right = 0;
        node->value = (unsigned char)counter;
        node->weight = frequencyTable[counter];

        if (node->weight == 0)
            node->weight = 1;  // 0 weights are illegal

        leafList[counter] = node; // Used later to generate the encryption table;
        huffmanEncodingTreeNodeList.insert(
            upper_bound(huffmanEncodingTreeNodeList.begin(),
                huffmanEncodingTreeNodeList.end(), node,
                cmp_node_weight), node);
    }

    //    for (auto& node : huffmanEncodingTreeNodeList)
    //    {
    //        printf("%d,%d\n", node->weight, node->value);
    //    }

    // 2.  While there is more than one node, take the two smallest trees and merge them
    // so that the two trees are the left and right children of a new node, where the new
    // node has the weight the sum of the weight of the left and right child nodes.
#ifdef _MSC_VER
#pragma warning( disable : 4127 ) // warning C4127: conditional expression is constant
#endif
    while (1) {
        HuffmanEncodingTreeNode *lesser, *greater;
        lesser = huffmanEncodingTreeNodeList.front();
        huffmanEncodingTreeNodeList.pop_front();
        greater = huffmanEncodingTreeNodeList.front();
        huffmanEncodingTreeNodeList.pop_front();
        node = geco_new<HuffmanEncodingTreeNode>(FILE_AND_LINE);
        node->left = lesser;
        node->right = greater;
        node->weight = lesser->weight + greater->weight;
        lesser->parent = node; // This is done to make generating the encryption table easier
        greater->parent = node; // This is done to make generating the encryption table easier

        if (huffmanEncodingTreeNodeList.size() == 0) {
            // 3. Assign the one remaining node in the list to the root node.
            root = node;
            root->parent = 0;
            //printf("node list is empty\n");
            break;
        }

        // Put the new node back into the list at the correct spot to maintain the sort.  Linear search time
        huffmanEncodingTreeNodeList.insert(
            upper_bound(huffmanEncodingTreeNodeList.begin(),
                huffmanEncodingTreeNodeList.end(), node,
                cmp_node_weight), node);
    }

    bool tempPath[256];  // Maximum path length is 256
    unsigned short tempPathLength;
    HuffmanEncodingTreeNode *currentNode;
    geco_bit_stream_t bitStream;

    // Generate the encryption table. From before, we have an array of pointers to all the leaves which
    // contain pointers to their parents. This can be done more efficiently but this isn't bad and it's way
    // easier to program and debug

    for (counter = 0; counter < 256; counter++) {
        // Already done at the end of the loop and before it!
        tempPathLength = 0;

        // Set the current node at the leaf
        currentNode = leafList[counter];

        do {
            // We're storing the paths in reverse order.since we are going from the leaf to the root
            if (currentNode->parent->left == currentNode)
                tempPath[tempPathLength++] = false;
            else
                tempPath[tempPathLength++] = true;
            currentNode = currentNode->parent;
        } while (currentNode != root);

        // Write to the bitstream in the reverse order that we stored the path,
        // which gives us the correct order from the root to the leaf
        while (tempPathLength-- > 0) {
            // Write 1's and 0's because writing a bool will write the JackieBits TYPE_CHECKING validation bits
            // if that is defined along with the actual data bit, which is not what we want
            if (tempPath[tempPathLength])
                bitStream.WriteBitOne();
            else
                bitStream.WriteBitZero();
        }

        // Read data from the bitstream, which is written to the encoding table in bits and bitlength.
        // Note this function allocates the encodingTable[counter].encoding pointer
        encodingTable[counter].encoding = (uchar*)geco_malloc_ext(
            bitStream.get_written_bytes(),
            FILE_AND_LINE);
        encodingTable[counter].bitLength = (unsigned short)bitStream.copy(
            encodingTable[counter].encoding, false);
        //        if (counter < 128)
        //        printf("letter %c\n", counter);
        //        else
        //            printf("letter %d\n", counter);
        //        bitStream.Bitify();
                // Reset the bitstream for the next one
        bitStream.reset();
        encodingTableSorted.push_back(&encodingTable[counter]);
    }
    std::sort(encodingTableSorted.begin(), encodingTableSorted.end(),
        cmp_char_encoding_bitslen);
}

// Pass an array of bytes to array and a preallocated JackieBits to receive the output
void HuffmanEncodingTree::EncodeArray(unsigned char *input, size_t sizeInBytes,
    geco_bit_stream_t * output) {
    unsigned counter;

    // For each input byte, Write out the corresponding series of 1's and 0's that give the encoded representation
    for (counter = 0; counter < sizeInBytes; counter++) {
        output->WriteBits(encodingTable[input[counter]].encoding,
            encodingTable[input[counter]].bitLength, false); // Data is left aligned
    }

    // Byte align the output so the unassigned remaining bits don't equate to some actual value
    if ((output->get_written_bits() & 7) != 0) {
        // binary search an input that is longer than the remaining bits.  Write out part of it to pad the output to be byte aligned.
        unsigned short remainingBits = (unsigned short)(8
            - (output->get_written_bits() & 7));
        CharacterEncoding tmp = { 0, remainingBits };
        auto pos = upper_bound(encodingTableSorted.begin(),
            encodingTableSorted.end(), &tmp, cmp_char_encoding_bitslen);
        output->WriteBits((*pos)->encoding, remainingBits, false); // Data is left aligned
#ifdef _DEBUG
        assert(counter != 256);
        // Given 256 elements, we should always be able to find an input that would be >= 7 bits
#endif

    }
}
unsigned HuffmanEncodingTree::DecodeArray(geco_bit_stream_t * input,
    bit_size_t sizeInBits, size_t maxCharsToWrite, unsigned char *output) {
    HuffmanEncodingTreeNode * currentNode;
    unsigned outputWriteIndex;
    outputWriteIndex = 0;
    currentNode = root;

    // For each bit, go left if it is a 0 and right if it is a 1.
        // When we reach a leaf, that gives us the desired value and we restart from the root

    for (unsigned counter = 0; counter < sizeInBits; counter++) {
        if (input->ReadBit() == false)   // left!
            currentNode = currentNode->left;
        else
            currentNode = currentNode->right;

        if (currentNode->left == 0 && currentNode->right == 0)   // Leaf
        {
            if (outputWriteIndex < maxCharsToWrite)
                output[outputWriteIndex] = currentNode->value;
            outputWriteIndex++;
            currentNode = root;
        }
    }

    return outputWriteIndex;
}
// Pass an array of encoded bytes to array and a preallocated JackieBits to receive the output
void HuffmanEncodingTree::DecodeArray(unsigned char *input,
    bit_size_t sizeInBits, geco_bit_stream_t * output) {
    HuffmanEncodingTreeNode * currentNode;
    if (sizeInBits <= 0)
        return;
    geco_bit_stream_t bitStream(input, BITS_TO_BYTES(sizeInBits), false);
    currentNode = root;

    // For each bit, go left if it is a 0 and right if it is a 1.  When we reach a leaf, that gives us the desired value and we restart from the root
    for (unsigned counter = 0; counter < sizeInBits; counter++) {
        if (bitStream.ReadBit() == false)   // left!
            currentNode = currentNode->left;
        else
            currentNode = currentNode->right;

        if (currentNode->left == 0 && currentNode->right == 0)   // Leaf
        {
            // Use WriteBits instead of Write(char) because we want to avoid TYPE_CHECKING
            output->WriteBits(&(currentNode->value), 8, true);
            currentNode = root;
        }
    }
}

geco_string_compressor_t* geco_string_compressor_t::instance = 0;
int geco_string_compressor_t::referenceCount = 0;

geco_string_compressor_t::geco_string_compressor_t()
    : huffmanEncodingTrees(32, (HuffmanEncodingTree*)NULL)
{
    // Make a default tree immediately,
    // since this is used for RPC possibly from multiple threads at the same time
#ifdef _DEBUG
    for (auto ptr : huffmanEncodingTrees)
    {
        assert(ptr == 0);
    }
#endif
    HuffmanEncodingTree *huffmanEncodingTree = geco_new<HuffmanEncodingTree>(
        FILE_AND_LINE);
    huffmanEncodingTree->GenerateFromFrequencyTable(
        englishCharacterFrequencies);
    huffmanEncodingTrees[0] = huffmanEncodingTree;
    //huffmanEncodingTrees.insert(std::make_pair(0, huffmanEncodingTree));
}

geco_string_compressor_t::~geco_string_compressor_t() {
    for (unsigned i = 0; i < huffmanEncodingTrees.size(); i++)
        geco_delete(huffmanEncodingTrees[i], FILE_AND_LINE);
}

void geco_string_compressor_t::AddReference(void) {
    if (++referenceCount == 1) {
        instance = geco_new<geco_string_compressor_t>(FILE_AND_LINE);
    }
}

void geco_string_compressor_t::RemoveReference(void) {
    assert(referenceCount > 0);

    if (referenceCount > 0) {
        if (--referenceCount == 0) {
            geco_delete(instance, FILE_AND_LINE);
            instance = 0;
        }
    }
}

void geco_string_compressor_t::EncodeString(const char *input,
    int maxCharsToWrite, geco_bit_stream_t *output, uchar languageId) {
    //HuffmanEncodingTree *huffmanEncodingTree;
    //if (huffmanEncodingTrees.find(languageId) == huffmanEncodingTrees.end())
    //	return;
    //huffmanEncodingTree = huffmanEncodingTrees.find(languageId)->second;

    HuffmanEncodingTree *huffmanEncodingTree = huffmanEncodingTrees[languageId];
    if (huffmanEncodingTree == NULL) return;

    if (input == 0) {
        output->WriteMini((uint)0);
        return;
    }

    geco_bit_stream_t encodedBitStream;
    uint stringBitLength;
    int charsToWrite;

    if (maxCharsToWrite <= 0 || (int)strlen(input) < maxCharsToWrite)
        charsToWrite = (int)strlen(input);
    else
        charsToWrite = maxCharsToWrite - 1;

    huffmanEncodingTree->EncodeArray((unsigned char*)input, charsToWrite,
        &encodedBitStream);
    stringBitLength = (uint)encodedBitStream.get_written_bits();
    output->WriteMini(stringBitLength);
    output->WriteBits(encodedBitStream.uchar_data(), stringBitLength);
}

bool geco_string_compressor_t::DecodeString(char *output, int maxCharsToWrite,
    geco_bit_stream_t *input, uchar languageId) {
    if (maxCharsToWrite <= 0)
        return false;
    //HuffmanEncodingTree *huffmanEncodingTree;
    //if (huffmanEncodingTrees.find(languageId) == huffmanEncodingTrees.end())
    //	return false;
    //huffmanEncodingTree = huffmanEncodingTrees.find(languageId)->second;
    HuffmanEncodingTree *huffmanEncodingTree = huffmanEncodingTrees[languageId];
    if (huffmanEncodingTree == NULL) return false;

    uint stringBitLength = 0;
    int bytesInStream;
    output[0] = 0;

    input->ReadMini(stringBitLength);
    if (!stringBitLength)
        return false;

    if (input->get_payloads() < stringBitLength)
        return false;

    bytesInStream = huffmanEncodingTree->DecodeArray(input, stringBitLength,
        maxCharsToWrite, (unsigned char*)output);

    if (bytesInStream < maxCharsToWrite)
        output[bytesInStream] = 0;
    else
        output[maxCharsToWrite - 1] = 0;

    return true;
}

void geco_string_compressor_t::EncodeString(const std::string &input,
    int maxCharsToWrite, geco_bit_stream_t *output, uchar languageId) {
    EncodeString(input.c_str(), maxCharsToWrite, output, languageId);
}

geco_string_compressor_t* geco_string_compressor_t::Instance(void) {
    if (instance == 0)
        AddReference();
    return instance;
}

bool geco_string_compressor_t::DecodeString(std::string *output,
    int maxCharsToWrite, geco_bit_stream_t *input, uchar languageId) {
    if (maxCharsToWrite <= 0) {
        output->clear();
        return true;
    }

    char *destinationBlock;
    bool out;

#if USE_ALLOCA !=1
    if (maxCharsToWrite < GECO_STREAM_STACK_ALLOC_BYTES) {
        destinationBlock = (char*)alloca(maxCharsToWrite);
        out = DecodeString(destinationBlock, maxCharsToWrite, input, languageId);
        *output = destinationBlock;
    }
    else
#endif
    {
        destinationBlock = (char*)geco_malloc_ext(maxCharsToWrite, FILE_AND_LINE);
        out = DecodeString(destinationBlock, maxCharsToWrite, input, languageId);
        *output = destinationBlock;
        geco_free_ext(destinationBlock, FILE_AND_LINE);
    }
    return out;
}

geco_bit_stream_t::geco_bit_stream_t() :
    allocated_bits_size_(GECO_STREAM_STACK_ALLOC_BITS),
    writable_bit_pos_(0), readable_bit_pos_(0),
    uchar_data_(statck_buffer_),
    can_free_(false),
    is_read_only_(false)
{
    memset(uchar_data_, 0, GECO_STREAM_STACK_ALLOC_BYTES);
}

geco_bit_stream_t::geco_bit_stream_t(const bit_size_t initialBytesAllocate) :
    writable_bit_pos_(0), readable_bit_pos_(0), is_read_only_(false) {
    if (initialBytesAllocate <= GECO_STREAM_STACK_ALLOC_BYTES) {
        uchar_data_ = statck_buffer_;
        allocated_bits_size_ = GECO_STREAM_STACK_ALLOC_BITS;
        can_free_ = false;
        assert(uchar_data_);
        memset(uchar_data_, 0, GECO_STREAM_STACK_ALLOC_BYTES);
    }
    else {

        //uchar_data_ = (uchar*) gMallocEx(initialBytesAllocate, TRACKE_MALLOC);
        uchar_data_ = (uchar*)malloc(initialBytesAllocate);
        allocated_bits_size_ = BYTES_TO_BITS(initialBytesAllocate);
        can_free_ = true;
        assert(uchar_data_);
        memset(uchar_data_, 0, initialBytesAllocate);
    }
}
geco_bit_stream_t::geco_bit_stream_t(uchar* src, const byte_size_t len,
    bool copy/*=false*/) :
    allocated_bits_size_(BYTES_TO_BITS(len)), writable_bit_pos_(
        BYTES_TO_BITS(len)), readable_bit_pos_(0), can_free_(false), is_read_only_(
            !copy) {
    if (copy) {
        if (len > 0) {
            if (len <= GECO_STREAM_STACK_ALLOC_BYTES) {
                uchar_data_ = statck_buffer_;
                allocated_bits_size_ = BYTES_TO_BITS(
                    GECO_STREAM_STACK_ALLOC_BYTES);
                memset(uchar_data_, 0, GECO_STREAM_STACK_ALLOC_BYTES);
            }
            else {
                // uchar_data_ = (uchar*) gMallocEx(len, TRACKE_MALLOC);
                uchar_data_ = (uchar*)malloc(len);
                can_free_ = true;
                memset(uchar_data_, 0, len);
            }
            memcpy(uchar_data_, src, len);
        }
        else {
            uchar_data_ = 0;
        }
    }
    else {
        uchar_data_ = src;
    }
}
geco_bit_stream_t::~geco_bit_stream_t() {
    if (can_free_ && allocated_bits_size_ > GECO_STREAM_STACK_ALLOC_BYTES) {
        // gFreeEx(uchar_data_, TRACKE_MALLOC);
        free(uchar_data_);
    }
}

void geco_bit_stream_t::ReadMini(uchar* dest, const bit_size_t bits2Read,
    bool isUnsigned) {
    uint currByte;
    uchar byteMatch;
    uchar halfByteMatch;

    if (isUnsigned) {
        byteMatch = 0;
        halfByteMatch = 0;
    }
    else {
        byteMatch = 0xFF;
        halfByteMatch = 0xF0;
    }

    if (!IsBigEndian()) {
        currByte = (bits2Read >> 3) - 1;
        while (currByte > 0) {
            // If we read a 1 then the data is byteMatch.
            ReadMini(isUnsigned);
            if (!isUnsigned)  // Check that bit
            {
                //JINFO << "matched";
                dest[currByte] = byteMatch;
                currByte--;
            }
            else  /// the first byte is not matched
            {
                // Read the rest of the bytes
                ReadBits(dest, (currByte + 1) << 3);
                return;
            }
        }
        assert(currByte == 0);
    }
    else {
        currByte = 0;
        while (currByte < ((bits2Read >> 3) - 1)) {
            // If we read a bit 0 then the data is byteMatch.
            ReadMini(isUnsigned);
            if (!isUnsigned)  // Check that bit
            {
                //JINFO << "matched";
                dest[currByte] = byteMatch;
                currByte++;
            }
            else  /// the first byte is not matched
            {
                // Read the rest of the bytes
                ReadBits(dest, bits2Read - (currByte << 3));
                return;
            }
        }
    }

    // If this assert is hit the stream wasn't long enough to read from
    assert(get_payloads() >= 1);

    /// the upper(left aligned) half of the last byte(now currByte == 0) is a 0000
    /// (positive) or 1111 (nagative) write a bit 0 and the remaining 4 bits.
    ReadMini(isUnsigned);
    if (!isUnsigned) {
        ReadBits(dest + currByte, 4);
        // read the remaining 4 bits
        dest[currByte] |= halfByteMatch;
    }
    else {
        ReadBits(dest + currByte, 8);
    }
}

void geco_bit_stream_t::AppendBitsCouldRealloc(const bit_size_t bits2Append) {
    bit_size_t newBitsAllocCount = bits2Append + writable_bit_pos_; /// official
//bit_size_t newBitsAllocCount = bits2Append + mWritingPosBits + 1;

// If this assert hits then we need to specify mReadOnly as false
// It needs to reallocate to hold all the data and can't do it unless we allocated to begin with
// Often hits if you call Write or Serialize on a read-only bitstream
    assert(is_read_only_ == false);

    //if (newBitsAllocCount > 0 && ((mBitsAllocSize - 1) >> 3) < // official
    //  ((newBitsAllocCount - 1) >> 3))

    /// see if one or more new bytes need to be allocated
    if (allocated_bits_size_ < newBitsAllocCount) {
        // Less memory efficient but saves on news and deletes
        /// Cap to 1 meg buffer to save on huge allocations
        // [11/16/2015 JACKIE]
        /// fix bug: newBitsAllocCount should plus 1MB if < 1MB, otherwise it should doule itself
        if (newBitsAllocCount > 1048576) /// 1024B*1024 = 1048576B = 1024KB = 1MB
            newBitsAllocCount += 1048576;
        else
            newBitsAllocCount <<= 1;
        // Use realloc and free so we are more efficient than delete and new for resizing
        bit_size_t bytes2Alloc = BITS_TO_BYTES(newBitsAllocCount);
        if (uchar_data_ == statck_buffer_) {
            if (bytes2Alloc > GECO_STREAM_STACK_ALLOC_BYTES) {
                //　uchar_data_ = (uchar *) gMallocEx(bytes2Alloc, TRACKE_MALLOC);
                uchar_data_ = (uchar *)malloc(bytes2Alloc);
                if (writable_bit_pos_ > 0)
                    memcpy(uchar_data_, statck_buffer_,
                        BITS_TO_BYTES(allocated_bits_size_));
                can_free_ = true;
            }
        }
        else {
            /// if allocate new memory, old data is copied and old memory is frred
            //uchar_data_ = (uchar*) gReallocEx(uchar_data_, bytes2Alloc,TRACKE_MALLOC);
            uchar_data_ = (uchar*)realloc(uchar_data_, bytes2Alloc);
            can_free_ = true;
        }

        assert(uchar_data_ != 0);
    }

    if (newBitsAllocCount > allocated_bits_size_)
        allocated_bits_size_ = newBitsAllocCount;
}

void geco_bit_stream_t::ReadBits(uchar *dest, bit_size_t bits2Read,
    bool alignRight /*= true*/) {
    /// Assume bits to write are 10101010+00001111,
    /// bits2Write = 4, rightAligned = true, and so
    /// @mWritingPosBits = 5   @startWritePosBits = 5&7 = 5
    ///
    /// |<-------data[0]------->|     |<---------data[1]------->|
    ///+++++++++++++++++++++++++++++++++++
    /// | 0 |  1 | 2 | 3 |  4 | 5 |  6 | 7 | 8 |  9 |10 |11 |12 |13 |14 | 15 |  src bits index
    ///+++++++++++++++++++++++++++++++++++
    /// | 0 |  0 | 0 | 1 |  0 | 0 |  0 | 0 | 0 |  0 |  0 |  0 |  0  |  0 |  0 |   0 |  src  bits in memory
    ///+++++++++++++++++++++++++++++++++++
    ///
    /// start write first 3 bits 101 after shifting to right by , 00000 101
    /// write result                                                                      00010 101

    assert(bits2Read > 0);
    assert(get_payloads() >= bits2Read);
    //if (bits2Read <= 0 || bits2Read > get_payloads()) return;

    /// get offset that overlaps one byte boudary, &7 is same to %8, but faster
    const bit_size_t startReadPosBits = readable_bit_pos_ & 7;

    /// byte position where start to read
    byte_size_t readPosByte = readable_bit_pos_ >> 3;

    if (startReadPosBits == 0 && (bits2Read & 7) == 0) {
        memcpy(dest, uchar_data_ + (readable_bit_pos_ >> 3), bits2Read >> 3);
        readable_bit_pos_ += bits2Read;
        return;
    }

    /// if @mReadPosBits is aligned  do memcpy for efficiency
    if (startReadPosBits == 0) {
        memcpy(dest, &uchar_data_[readPosByte], BITS_TO_BYTES(bits2Read));
        readable_bit_pos_ += bits2Read;

        /// if @bitsSize is not multiple times of 8,
        /// process the last read byte to shit the bits
        bit_size_t offset = bits2Read & 7;
        if (offset > 0) {
            if (alignRight)
                dest[BITS_TO_BYTES(bits2Read) - 1] >>= (8 - offset);
            else
                dest[BITS_TO_BYTES(bits2Read) - 1] |= 0;
        }
        return;
    }

    bit_size_t writePosByte = 0;
    memset(dest, 0, BITS_TO_BYTES(bits2Read));  /// Must set all 0

/// Read one complete byte each time
    while (bits2Read > 0) {
        readPosByte = readable_bit_pos_ >> 3;

        /// firstly read left-fragment bits in this byte
        dest[writePosByte] |= (uchar_data_[readPosByte] << (startReadPosBits));

        /// secondly read right-fragment bits  ( if any ) in this byte
        if (startReadPosBits > 0 && bits2Read > (8 - startReadPosBits)) {
            dest[writePosByte] |= uchar_data_[readPosByte + 1]
                >> (8 - startReadPosBits);
        }

        if (bits2Read >= 8) {
            bits2Read -= 8;
            readable_bit_pos_ += 8;
            writePosByte++;
        }
        else {
            // Reading a partial byte for the last byte, shift right so the data is aligned on the right
            //  [11/16/2015 JACKIE] Add: zero unused bits
            if (alignRight)
                dest[writePosByte] >>= (8 - bits2Read); /// right align result byte: 0000 1111
            else
                dest[writePosByte] |= 0;  /// left align result byte: 1111 0000
            //[11/15/2015 JACKIE] fix bug of not incrementing mReadingPosBits
            readable_bit_pos_ += bits2Read;
            bits2Read = 0;
        }
    }
}

void geco_bit_stream_t::read_ranged_float(float &outFloat, float floatMin,
    float floatMax) {
    assert(floatMax > floatMin);
    ushort percentile;
    ReadMini(percentile);
    outFloat = floatMin
        + ((float)percentile / 65535.0f) * (floatMax - floatMin);
    if (outFloat < floatMin)
        outFloat = floatMin;
    else if (outFloat > floatMax)
        outFloat = floatMax;
}

void geco_bit_stream_t::ReadAlignedBytes(uchar *dest,
    const byte_size_t bytes2Read) {
    //    assert(bytes2Read > 0);
    //    assert(get_payloads() >= BYTES_TO_BITS(bytes2Read));
    if (bytes2Read <= 0 || get_payloads() < BYTES_TO_BITS(bytes2Read))
        return;
    // Byte align
    align_readable_bit_pos();
    // read the data
    memcpy(dest, uchar_data_ + (readable_bit_pos_ >> 3), bytes2Read);
    readable_bit_pos_ += (bytes2Read << 3);
}

void geco_bit_stream_t::ReadAlignedBytes(char *dest, byte_size_t &bytes2Read,
    const byte_size_t maxBytes2Read) {
    ReadMini(bytes2Read);
    if (bytes2Read > maxBytes2Read)
        bytes2Read = maxBytes2Read;
    if (bytes2Read == 0)
        return;
    ReadAlignedBytes((uchar*)dest, bytes2Read);
}

void geco_bit_stream_t::ReadAlignedBytesAlloc(char **dest,
    byte_size_t &bytes2Read, const byte_size_t maxBytes2Read) {
    if (*dest != NULL) {
        //gFreeEx(*dest, TRACKE_MALLOC);
        free(*dest);
        *dest = 0;
    }
    ReadMini(bytes2Read);
    if (bytes2Read > maxBytes2Read)
        bytes2Read = maxBytes2Read;
    if (bytes2Read == 0)
        return;
    // *dest = (char*) gMallocEx(bytes2Read, TRACKE_MALLOC);
    *dest = (char*)malloc(bytes2Read);
    ReadAlignedBytes((uchar*)*dest, bytes2Read);
}

void geco_bit_stream_t::WriteBits(const uchar* src, bit_size_t bits2Write,
    bool rightAligned /*= true*/) {
    /// Assume bits to write are 10101010+00001111,
    /// bits2Write = 4, rightAligned = true, and so
    /// @mWritingPosBits = 5   @startWritePosBits = 5&7 = 5
    ///
    /// |<-------data[0]------->|     |<---------data[1]------->|
    ///+++++++++++++++++++++++++++++++++++
    /// | 0 |  1 | 2 | 3 |  4 | 5 |  6 | 7 | 8 |  9 |10 |11 |12 |13 |14 | 15 |  src bits index
    ///+++++++++++++++++++++++++++++++++++
    /// | 0 |  0 | 0 | 1 |  0 | 0 |  0 | 0 | 0 |  0 |  0 |  0 |  0  |  0 |  0 |   0 |  src  bits in memory
    ///+++++++++++++++++++++++++++++++++++
    ///
    /// start write first 3 bits 101 after shifting to right by , 00000 101
    /// write result                                                                      00010 101

    if (is_read_only_ || !bits2Write)
        return;

    //if( mReadOnly ) return false;
    //if( bits2Write == 0 ) return false;

    AppendBitsCouldRealloc(bits2Write);

    /// get offset that overlaps one byte boudary, &7 is same to %8, but faster
    /// @startWritePosBits could be zero
    const bit_size_t startWritePosBits = writable_bit_pos_ & 7;

    // If currently aligned and numberOfBits is a multiple of 8, just memcpy for speed
    if (startWritePosBits == 0 && (bits2Write & 7) == 0) {
        memcpy(uchar_data_ + (writable_bit_pos_ >> 3), src, bits2Write >> 3);
        writable_bit_pos_ += bits2Write;
        return;
    }

    uchar dataByte;
    //const uchar* inputPtr = src;

    while (bits2Write > 0) {
        dataByte = *(src++);

        /// if @dataByte is the last byte to write, we have to convert this byte into
        /// stream internal data by shifting the bits in this last byte to left-aligned
        if (bits2Write < 8 && rightAligned)
            dataByte <<= 8 - bits2Write;

        /// The folowing if-else block will write one byte each time
        if (startWritePosBits == 0) {
            /// startWritePosBits == 0  means there are no overlapped bits to be further
            /// processed and so we can directly write @dataByte into stream
            uchar_data_[writable_bit_pos_ >> 3] = dataByte;
        }
        else {
            /// startWritePosBits != 0 means there are  overlapped bits to be further
            /// processed and so we cannot directly write @dataBytedirectly into stream
            /// we have process overlapped bits before writting
            /// firstly write the as the same number of bits from @dataByte intot
            /// @data[mWritePosBits >> 3] to that in the right-half of
            /// @data[mWritePosBits >> 3]
            uchar_data_[writable_bit_pos_ >> 3] |= dataByte
                >> startWritePosBits;

            /// then to see if we have remaining bits in @dataByte to write
            /// 1. startWritePosBits > 0 means @data[mWritePosBits >> 3] is a partial byte
            /// 2. bits2Write > ( 8 - startWritePosBits ) means the rest space in
            /// @data[mWritePosBits >> 3] cannot hold all remaining bits in @dataByte
            /// we have to write these reamining bits to the next byte
            assert(startWritePosBits > 0);
            if (bits2Write > (8 - startWritePosBits)) {
                /// write remaining bits into the  byte next to @data[mWritePosBits >> 3]
                uchar_data_[(writable_bit_pos_ >> 3) + 1] = (dataByte
                    << (8 - startWritePosBits));
            }
        }

        /// we wrote one complete byte in above codes just now
        if (bits2Write >= 8) {
            writable_bit_pos_ += 8;
            bits2Write -= 8;
        }
        else ///  it is the last (could be partial) byte we wrote in the above codes,
        {
            writable_bit_pos_ += bits2Write;
            bits2Write = 0;
        }
    }
}
void geco_bit_stream_t::Write(geco_bit_stream_t *jackieBits,
    bit_size_t bits2Write) {
    assert(is_read_only_ == false);
    assert(bits2Write > 0);
    assert(bits2Write <= jackieBits->get_payloads());

    AppendBitsCouldRealloc(bits2Write);
    bit_size_t numberOfBitsMod8 = (jackieBits->readable_bit_pos_ & 7);
    bit_size_t newBits2Read = 8 - numberOfBitsMod8;

    /// write some bits to make @mReadingPosBits aligned to next byte boudary
    if (newBits2Read > 0) {
        while (newBits2Read-- > 0) {
            numberOfBitsMod8 = writable_bit_pos_ & 7;
            if (numberOfBitsMod8 == 0) {
                /// see if this src bit  is 1 or 0, 0x80 (16)= 128(10)= 10000000 (2)
                if ((jackieBits->uchar_data_[jackieBits->readable_bit_pos_ >> 3]
                    & (0x80 >> (jackieBits->readable_bit_pos_ & 7))))
                    // Write 1
                    uchar_data_[writable_bit_pos_ >> 3] = 0x80;
                else
                    uchar_data_[writable_bit_pos_ >> 3] = 0;
            }
            else {
                /// see if this src bit  is 1 or 0, 0x80 (16)= 128(10)= 10000000 (2)
                if ((jackieBits->uchar_data_[jackieBits->readable_bit_pos_ >> 3]
                    & (0x80 >> (jackieBits->readable_bit_pos_ & 7)))) {
                    /// set dest bit to 1 if the src bit is 1,do-nothing if the src bit is 0
                    uchar_data_[writable_bit_pos_ >> 3] |= 0x80
                        >> (numberOfBitsMod8);
                }
                else {
                    uchar_data_[writable_bit_pos_ >> 3] |= 0;
                }
            }

            jackieBits->readable_bit_pos_++;
            writable_bit_pos_++;
        }
        bits2Write -= newBits2Read;
    }
    // call WriteBits() for efficient  because it writes one byte from src at one time much faster
    assert((jackieBits->readable_bit_pos_ & 7) == 0);
    WriteBits(&jackieBits->uchar_data_[jackieBits->readable_bit_pos_ >> 3],
        bits2Write, false);
    jackieBits->readable_bit_pos_ += bits2Write;
}

void geco_bit_stream_t::write_ranged_float(float src, float floatMin,
    float floatMax) {
    assert(floatMax > floatMin);
    assert(src < floatMax + .001f);
    assert(src >= floatMin - .001f);

    float percentile = 65535.0f * ((src - floatMin) / (floatMax - floatMin));
    if (percentile < 0.0f)
        percentile = 0.0;
    if (percentile > 65535.0f)
        percentile = 65535.0f;
    //Write((uint16_t)percentile);
    WriteMini((ushort)percentile);
}

void geco_bit_stream_t::WriteMini(const uchar* src, const bit_size_t bits2Write,
    const bool isUnsigned) {
    byte_size_t currByte;
    uchar byteMatch = isUnsigned ? 0 : 0xFF;  /// 0xFF=255=11111111

    if (!IsBigEndian()) {
        /// get the highest byte with highest index  PCs
        currByte = (bits2Write >> 3) - 1;

        ///  high byte to low byte,
        /// if high byte is a byteMatch then write a 1 bit.
        /// Otherwise write a 0 bit and then write the remaining bytes
        while (currByte > 0) {
            ///  If high byte is byteMatch (0 or 0xff)
            /// write a bit 0 ,  then it would have the same value shifted
            if (src[currByte] == byteMatch) {
                Write(false);
                currByte--;
            }
            else  /// the first byte is not matched
            {
                Write(true);
                // Write the remainder of the data after writing bit true
                WriteBits(src, (currByte + 1) << 3);
                return;
            }
        }
        /// make sure we are now on the lowest byte (index 0)
        assert(currByte == 0);
    }
    else {
        /// get the highest byte with highest index  PCs
        currByte = 0;

        ///  high byte to low byte,
        /// if high byte is a byteMatch then write a 1 bit.
        /// Otherwise write a 0 bit and then write the remaining bytes
        while (currByte < ((bits2Write >> 3) - 1)) {
            ///  If high byte is byteMatch (0 or 0xff)
            /// then it would have the same value shifted
            if (src[currByte] == byteMatch) {
                Write(false);
                currByte++;
            }
            else  /// the first byte is not matched
            {
                Write(true);
                // Write the remainder of the data after writing bit false
                WriteBits(src + currByte, bits2Write - (currByte << 3));
                return;
            }
        }
        /// make sure we are now on the lowest byte (index highest)
        assert(currByte == ((bits2Write >> 3) - 1));
    }

    /// last byte
    if ((src[currByte] & 0xF0) == 0x00 || (src[currByte] & 0xF0) == 0xF0) { /// the upper(left aligned) half of the last byte(now currByte == 0) is a 0000 (positive) or 1111 (nagative)
/// write a bit 0 and the remaining 4 bits.
        Write(false);
        WriteBits(src + currByte, 4);
    }
    else {        /// write a 1 and the remaining 8 bites.
        Write(true);
        WriteBits(src + currByte, 8);
    }
}

void geco_bit_stream_t::write_aligned_bytes(const uchar *src,
    const byte_size_t numberOfBytesWrite) {
    align_writable_bit_pos();
    Write((char*)src, numberOfBytesWrite);
}

void geco_bit_stream_t::write_aligned_bytes(const uchar *src,
    const byte_size_t bytes2Write, const byte_size_t maxBytes2Write) {
    WriteMini(bytes2Write);
    if (src == 0 || bytes2Write == 0) {
        return;
    }
    write_aligned_bytes(src,
        bytes2Write < maxBytes2Write ? bytes2Write : maxBytes2Write);
}

void geco_bit_stream_t::pad_zeros_up_to(uint bytes) {
    int numWrite = bytes - get_written_bytes();
    if (numWrite > 0) {
        align_writable_bit_pos();
        AppendBitsCouldRealloc(BYTES_TO_BITS(numWrite));
        memset(uchar_data_ + (writable_bit_pos_ >> 3), 0, numWrite);
        writable_bit_pos_ += BYTES_TO_BITS(numWrite);
    }
}

#define INTSIGNBITSET(i)		(((const unsigned long)(i)) >> 31)
#define IEEE_FLT_MANTISSA_BITS	23
#define IEEE_FLT_EXPONENT_BITS	8
#define IEEE_FLT_EXPONENT_BIAS	127
#define IEEE_FLT_SIGN_BIT		31

int geco_bit_stream_t::FloatToBits(float f, int exponentBits,
    int mantissaBits) {
    int i, sign, exponent, mantissa, value;

    assert(exponentBits >= 2 && exponentBits <= 8);
    assert(mantissaBits >= 2 && mantissaBits <= 23);

    int maxBits = (((1 << (exponentBits - 1)) - 1) << mantissaBits)
        | ((1 << mantissaBits) - 1);
    int minBits = (((1 << exponentBits) - 2) << mantissaBits) | 1;

    float max = BitsToFloat(maxBits, exponentBits, mantissaBits);
    float min = BitsToFloat(minBits, exponentBits, mantissaBits);

    if (f >= 0.0f) {
        if (f >= max) {
            return maxBits;
        }
        else if (f <= min) {
            return minBits;
        }
    }
    else {
        if (f <= -max) {
            return (maxBits | (1 << (exponentBits + mantissaBits)));
        }
        else if (f >= -min) {
            return (minBits | (1 << (exponentBits + mantissaBits)));
        }
    }

    exponentBits--;
    i = *reinterpret_cast<int *>(&f);
    sign = (i >> IEEE_FLT_SIGN_BIT) & 1;
    exponent = ((i >> IEEE_FLT_MANTISSA_BITS)
        & ((1 << IEEE_FLT_EXPONENT_BITS) - 1)) - IEEE_FLT_EXPONENT_BIAS;
    mantissa = i & ((1 << IEEE_FLT_MANTISSA_BITS) - 1);
    value = sign << (1 + exponentBits + mantissaBits);
    value |= ((INTSIGNBITSET(exponent) << exponentBits)
        | (abs(exponent) & ((1 << exponentBits) - 1))) << mantissaBits;
    value |= mantissa >> (IEEE_FLT_MANTISSA_BITS - mantissaBits);
    return value;
}

float geco_bit_stream_t::BitsToFloat(int i, int exponentBits,
    int mantissaBits) {
    static int exponentSign[2] = { 1, -1 };
    int sign, exponent, mantissa, value;

    assert(exponentBits >= 2 && exponentBits <= 8);
    assert(mantissaBits >= 2 && mantissaBits <= 23);

    exponentBits--;
    sign = i >> (1 + exponentBits + mantissaBits);
    exponent = ((i >> mantissaBits) & ((1 << exponentBits) - 1))
        * exponentSign[(i >> (exponentBits + mantissaBits)) & 1];
    mantissa = (i & ((1 << mantissaBits) - 1))
        << (IEEE_FLT_MANTISSA_BITS - mantissaBits);
    value = sign << IEEE_FLT_SIGN_BIT
        | (exponent + IEEE_FLT_EXPONENT_BIAS) << IEEE_FLT_MANTISSA_BITS
        | mantissa;
    return *reinterpret_cast<float *>(&value);
}

void geco_bit_stream_t::WriteMini(geco_bit_stream_t& src) {
    if (src.get_payloads() <= 0)
        return;
    this->AppendBitsCouldRealloc(src.get_payloads());
    uchar count = 0;
    uchar tmp = 0;
    uint writebits;
    while ((writebits = src.get_payloads()) > 0) {
        while (true) {
            if (writebits >= 3) {
                writebits = 3;
                src.ReadBits(&tmp, 3);
            }
            else {
                src.ReadBits(&tmp, writebits);
            }

            if (tmp == 0 && writebits == 3 && count < 256) {
                count++;
                if ((writebits = src.get_payloads()) == 0)
                    break;
            }
            else
                break;
        }

        if (count) {
            WriteBitZeros(3);
            WriteBits(&count, 8 - get_leading_zeros_size(count));
            count = 0;
        }
        if (writebits > 0)
            WriteBits(&tmp, writebits);
    }
}
void geco_bit_stream_t::ReadMini(geco_bit_stream_t& dest) {
    if (get_payloads() <= 0)
        return;
    dest.AppendBitsCouldRealloc(this->get_payloads());
    uchar count = 0;
    uchar tmp = 0;
    uint remaining_bits_size;
    while ((remaining_bits_size = dest.get_payloads()) > 0) {
        if (remaining_bits_size >= 3) {
            remaining_bits_size = 3;
            ReadBits(&tmp, 3);
        }
        else
            ReadBits(&tmp, remaining_bits_size);

        if (tmp == 0) {
            ReadMini(count);
            while (count-- > 0) {
                dest.WriteBitZeros(3);
            }
        }
        else {
            dest.WriteBits(&tmp, remaining_bits_size);
        }
    }
}
void geco_bit_stream_t::Bitify(char* out, int mWritePosBits,
    unsigned char* mBuffer, bool hide_zero_low_bytes) {
    printf(
        "[%dbits %dbytes]\ntop (low byte)-> bottom (high byte),\nright(low bit)->left(high bit):\n",
        mWritePosBits, BITS_TO_BYTES(mWritePosBits));

    if (mWritePosBits <= 0) {
        strcpy(out, "no bits to print\n");
        return;
    }

    int strIndex = 0;
    int inner;
    int stopPos;
    int outter;
    int len = BITS_TO_BYTES(mWritePosBits);
    bool first_1 = true;
    uint zeros = 0, ones = 0;

    for (outter = 0; outter < len; outter++) {
        if (outter == len - 1)
            stopPos = 8 - (((mWritePosBits - 1) & 7) + 1);
        else
            stopPos = 0;

        for (inner = 7; inner >= stopPos; inner--) {
            if ((mBuffer[outter] >> inner) & 1) {
                if (hide_zero_low_bytes && first_1 && strIndex >= 8) {
                    strIndex = (strIndex & 7) + 2;
                    first_1 = false;
                }
                out[strIndex++] = '1';
                ones++;
            }
            else {
                out[strIndex++] = '0';
                zeros++;
            }
        }
        out[strIndex++] = '\n';
    }

    out[strIndex++] = '\n';
    out[strIndex++] = 0;

    printf("zeros %zu, ones %zu, \n", zeros, ones);
}
void geco_bit_stream_t::Bitify(bool hide_zero_low_bytes) {
    char out[4096 * 8];
    Bitify(out, writable_bit_pos_, uchar_data_, hide_zero_low_bytes);
    printf("%s\n", out);
}
void geco_bit_stream_t::Hexlify(char* out, bit_size_t mWritePosBits,
    uchar* mBuffer) {
    if (mWritePosBits <= 0) {
        strcpy(out, "no bytes to print\n");
        return;
    }
    for (bit_size_t Index = 0; Index < BITS_TO_BYTES(mWritePosBits); Index++) {
        sprintf(out + Index * 3, "%02x ", mBuffer[Index]);
    }
}
void geco_bit_stream_t::Hexlify(void) {
    char out[4096];
    geco_bit_stream_t::Hexlify(out, writable_bit_pos_, uchar_data_);
    printf("%s\n", out);
}
