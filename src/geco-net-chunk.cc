#include "geco-net-chunk.h"
#include "geco-malloc.h"
#include <cassert>

/*related to simple chunk send */
uint curr_write_pos_[MAX_CHUNKS_SIZE]; /* where is the next write starts */
simple_chunk_t* simple_chunks_[MAX_CHUNKS_SIZE]; /* simple ctrl chunks to send*/
//simple_chunk_t simple_chunks_pods_[MAX_CHUNKS_SIZE]; /* simple ctrl chunks to send*/
bool completed_chunks_[MAX_CHUNKS_SIZE];/*if a chunk is completely constructed*/
uint simple_chunk_index_ = 0; /* current simple chunk index */
simple_chunk_t* simple_chunk_t_ptr_ = NULL; /* current simple chunk ptr */

simple_chunk_t* mch_read_simple_chunk(uint chunkID)
{
	return simple_chunks_[chunkID];
}
simple_chunk_t** mch_read_simple_chunks()
{
	return simple_chunks_;
}

uchar* mch_read_vlparam_init_chunk(uchar * setup_chunk, uint chunk_len,
	ushort param_type)
{
	/*1) validate packet length*/
	uint read_len = CHUNK_FIXED_SIZE + INIT_CHUNK_FIXED_SIZE;
	if (setup_chunk == NULL || chunk_len < read_len)
	{
		return NULL;
	}

	/*2) validate chunk id inside this chunk*/
	init_chunk_t* init_chunk = (init_chunk_t*)setup_chunk;
	if (init_chunk->chunk_header.chunk_id != CHUNK_INIT
		&& init_chunk->chunk_header.chunk_id != CHUNK_INIT_ACK)
	{
		return NULL;
	}

	uint len = ntohs(init_chunk->chunk_header.chunk_length);
	uchar* curr_pos = setup_chunk + read_len;

	ushort vlp_len;
	uint padding_len;
	vlparam_fixed_t* vlp;

	/*3) parse all vlparams in this chunk*/
	while (read_len < len)
	{
		EVENTLOG2(VVERBOSE,
			"find_params_from_setup_chunk() : len==%u, processed_len == %u",
			len, read_len);

		if (len - read_len < VLPARAM_FIXED_SIZE)
		{
			return NULL;
		}

		vlp = (vlparam_fixed_t*)(curr_pos);
		vlp_len = ntohs(vlp->param_length);
		if (vlp_len < VLPARAM_FIXED_SIZE || vlp_len + read_len > len)
		{
			return NULL;
		}

		/*4) find param in this chunk*/
		if (ntohs(vlp->param_type) == param_type)
		{
			EVENTLOG1(VERBOSE,
				"find_params_from_setup_chunk() : Founf chunk type %d-> return",
				param_type);
			return curr_pos;
		}

		read_len += vlp_len;
		padding_len = ((read_len & 3) == 0) ? 0 : (4 - (read_len & 3));
		read_len += padding_len;
		curr_pos = setup_chunk + read_len;
	}  // while

	return NULL;
}

chunk_id_t mch_make_init_chunk_from_cookie(
	cookie_echo_chunk_t* cookie_echo_chunk)
{
	assert(cookie_echo_chunk != NULL);
	init_chunk_t* initChunk = (init_chunk_t*)geco_malloc_ext(
		INIT_CHUNK_TOTAL_SIZE,
		__FILE__,
		__LINE__);
	if (initChunk == NULL)
		ERRLOG(FALTAL_ERROR_EXIT, "malloc failed!\n");
	memset(initChunk, 0, INIT_CHUNK_TOTAL_SIZE);
	initChunk->chunk_header.chunk_id = CHUNK_INIT;
	initChunk->chunk_header.chunk_flags = 0x00;
	initChunk->chunk_header.chunk_length = INIT_CHUNK_FIXED_SIZES;
	initChunk->init_fixed = cookie_echo_chunk->cookie.peer_init;
	return add2chunklist((simple_chunk_t*)initChunk,
		"add2chunklist()::created initChunk  from cookie %u");
}
chunk_id_t mch_make_init_ack_chunk_from_cookie(
	cookie_echo_chunk_t* cookie_echo_chunk)
{
	assert(cookie_echo_chunk != NULL);
	init_chunk_t* initChunk = (init_chunk_t*)geco_malloc_ext(
		INIT_CHUNK_TOTAL_SIZE,
		__FILE__,
		__LINE__);
	if (initChunk == NULL)
		ERRLOG(FALTAL_ERROR_EXIT, "malloc failed!\n");
	memset(initChunk, 0, INIT_CHUNK_TOTAL_SIZE);
	initChunk->chunk_header.chunk_id = CHUNK_INIT_ACK;
	initChunk->chunk_header.chunk_flags = 0x00;
	initChunk->chunk_header.chunk_length = INIT_CHUNK_FIXED_SIZES;
	initChunk->init_fixed = cookie_echo_chunk->cookie.local_initack;
	return add2chunklist((simple_chunk_t*)initChunk,
		"add2chunklist()::created init ack chunk  from cookie %u");
}

uint mch_read_rwnd(uint chunkID)
{
	if (simple_chunks_[chunkID] == NULL)
	{
		ERRLOG(MAJOR_ERROR, "Invalid chunk ID");
		return 0;
	}

	if (simple_chunks_[chunkID]->chunk_header.chunk_id == CHUNK_INIT_ACK
		|| simple_chunks_[chunkID]->chunk_header.chunk_id == CHUNK_INIT)
	{
		return ntohl(((init_chunk_t*)simple_chunks_[chunkID])->init_fixed.rwnd);
	}
	else
	{
		ERRLOG(MAJOR_ERROR, "mch_read_rwnd: chunk type not init or initAck");
		return 0;
	}
	return 0;
}

uint mch_read_itsn(uint chunkID)
{
	if (simple_chunks_[chunkID] == NULL)
	{
		ERRLOG(MAJOR_ERROR, "Invalid chunk ID");
		return 0;
	}

	if (simple_chunks_[chunkID]->chunk_header.chunk_id == CHUNK_INIT_ACK
		|| simple_chunks_[chunkID]->chunk_header.chunk_id == CHUNK_INIT)
	{
		return ntohl(
			((init_chunk_t*)simple_chunks_[chunkID])->init_fixed.initial_tsn);
	}
	else
	{
		ERRLOG(MAJOR_ERROR, "mch_read_itsn: chunk type not init or initAck");
		return 0;
	}
	return 0;
}

chunk_id_t mch_make_cookie_echo(cookie_param_t * cookieParam)
{
	if (cookieParam == 0)
		return -1;

	cookie_echo_chunk_t* cookieChunk = (cookie_echo_chunk_t*)geco_malloc_ext(
		sizeof(cookie_echo_chunk_t), __FILE__,
		__LINE__);
	cookieChunk->chunk_header.chunk_id = CHUNK_COOKIE_ECHO;
	cookieChunk->chunk_header.chunk_flags = 0x00;
	cookieChunk->chunk_header.chunk_length = ntohs(
		cookieParam->vlparam_header.param_length);
	add2chunklist((simple_chunk_t*)cookieChunk,
		"created cookie echo chunk %u ");
	/*  copy cookie parameter EXcluding param-header into chunk */
	memcpy(&(cookieChunk->cookie),
		&cookieParam->ck,
		cookieChunk->chunk_header.chunk_length - VLPARAM_FIXED_SIZE);
	return simple_chunk_index_;
}

uint mch_read_cookie_preserve(uint chunkID,
	bool ignore_cookie_life_spn_from_init_chunk_, uint defaultcookielife)
{
	if (simple_chunks_[chunkID] == NULL)
	{
		ERRLOG(MAJOR_ERROR, "Invalid chunk ID");
		return 0;
	}

	if (simple_chunks_[chunkID]->chunk_header.chunk_id != CHUNK_INIT)
	{
		ERRLOG(MAJOR_ERROR, "mch_read_cookie_preserve()::chunk type not init");
		return 0;
	}

	init_chunk_t* init = ((init_chunk_t*)simple_chunks_[chunkID]);
	uint vlparams_len = ntohs(
		init->chunk_header.chunk_length) - INIT_CHUNK_FIXED_SIZES;
	uchar* curr_pos = mch_read_vlparam(VLPARAM_COOKIE_PRESEREASONV,
		init->variableParams, vlparams_len);
	if (curr_pos != NULL && !ignore_cookie_life_spn_from_init_chunk_)
	{
		/* found cookie preservative */
		return ntohl(((cookie_preservative_t*)curr_pos)->cookieLifetimeInc)
			+ defaultcookielife;
	}
	else
	{
		/* return default cookie life span*/
		return defaultcookielife;
	}
	return 0;
}

int mch_validate_init_vlps(uint src_cid, uint dest_cid)
{
#ifdef _DEBUG
	EVENTLOG(VERBOSE, "- - - Enter mch_validate_init_vlps()");
#endif

	if (simple_chunks_[src_cid] == NULL || simple_chunks_[dest_cid] == NULL)
	{
		ERRLOG(FALTAL_ERROR_EXIT, "mch_write_cookie()::Invalid chunk ID");
		return -1;
	}

	init_chunk_t* chunk = ((init_chunk_t*)simple_chunks_[src_cid]);
	uchar* curr_vlp_start = chunk->variableParams;
	uint total_len_vlps = chunk->chunk_header.chunk_length
		- INIT_CHUNK_FIXED_SIZES;

	uint read_len = 0;
	ushort pType;
	ushort pLen;
	vlparam_fixed_t* vlparam_fixed;
	int ret = 0;

	while (read_len < total_len_vlps)
	{
		if (total_len_vlps - read_len < VLPARAM_FIXED_SIZE)
		{
			EVENTLOG(WARNNING_ERROR,
				"remainning bytes not enough for VLPARAM_FIXED_SIZE(4 bytes) invalid !");
			return -1;
		}
		//init_ack_str = &chunk->variableParams[curr_write_pos_[dest_chunk_cid]];
		vlparam_fixed = (vlparam_fixed_t*)&curr_vlp_start[read_len];
		pType = ntohs(vlparam_fixed->param_type);
		pLen = ntohs(vlparam_fixed->param_length);
		// vlp length too short or patial vlp problem
		if (pLen < VLPARAM_FIXED_SIZE || pLen + read_len > total_len_vlps)
			return -1;

		/* handle unrecognized geco_instance_params */
		else if (pType != VLPARAM_COOKIE_PRESEREASONV
			&& pType != VLPARAM_SUPPORTED_ADDR_TYPES
			&& pType != VLPARAM_IPV4_ADDRESS
			&& pType != VLPARAM_IPV6_ADDRESS
			&& pType != VLPARAM_UNRELIABILITY && pType != VLPARAM_ADDIP
			&& pType != VLPARAM_COOKIE_PRESEREASONV
			&& pType != VLPARAM_COOKIE && pType != VLPARAM_SET_PRIMARY
			&& pType != VLPARAM_UNRELIABILITY)
		{
			if (STOP_PROCESS_PARAM(pType))
			{
				EVENTLOG2(NOTICE,
					"found unknown parameter type %u len %u in message -> stop",
					pType, pLen);
				mch_write_error_cause(dest_cid, VLPARAM_UNRECOGNIZED_PARAM,
					curr_vlp_start, pLen);
				return ActionWhenUnknownVlpOrChunkType::STOP_PROCESS_PARAM;
			}
			else if (STOP_PROCES_PARAM_REPORT_EREASON(pType))
			{
				EVENTLOG2(NOTICE,
					"found unknown parameter type %u len %u in message -> stop and report",
					pType, pLen);
				mch_write_error_cause(dest_cid, VLPARAM_UNRECOGNIZED_PARAM,
					curr_vlp_start, pLen);
				return ActionWhenUnknownVlpOrChunkType::STOP_PROCES_PARAM_REPORT_EREASON;
			}
			else if (SKIP_PARAM_REPORT_EREASON(pType))
			{
				EVENTLOG2(NOTICE,
					"found unknown parameter type %u len %u in message -> skip and report",
					pType, pLen);
				mch_write_error_cause(dest_cid, VLPARAM_UNRECOGNIZED_PARAM,
					curr_vlp_start, pLen);
				ret =
					ActionWhenUnknownVlpOrChunkType::SKIP_PARAM_REPORT_EREASON;
			}
			else if (SKIP_PARAM(pType))
			{
				EVENTLOG2(NOTICE,
					"found unknown parameter type %u len %u in message -> skip",
					pType, pLen);
				ret = ActionWhenUnknownVlpOrChunkType::SKIP_PARAM;
			}
		}
		read_len += pLen;
		while (read_len & 3)
			read_len++;
	}

#ifdef _DEBUG
	if (ret == 0)
		EVENTLOG1(DEBUG, "Not find unknown parameter types (ret=%d)", ret);
	EVENTLOG(VERBOSE, "- - - Leave mch_validate_init_vlps()");
#endif
	return ret;
}

uchar* mch_read_vlparam(uint vlp_type, uchar* vlp_fixed, uint len)
{
	ushort vlp_len;
	uint padding_len;
	uint read_len = 0;
	uint vlptype;
	vlparam_fixed_t* vlp;

	while (read_len < len)
	{
		/*1) validate reset of space of packet*/
		if (len - read_len < VLPARAM_FIXED_SIZE)
		{
			EVENTLOG(WARNNING_ERROR,
				"remainning bytes not enough for VLPARAM_FIXED_SIZE(4 bytes) invalid !\n");
			return NULL;
		}

		vlp = (vlparam_fixed_t*)&vlp_fixed[read_len];
		vlptype = ntohs(vlp->param_type);
		vlp_len = ntohs(vlp->param_length);
		if (vlp_len < VLPARAM_FIXED_SIZE || vlp_len + read_len > len)
			return NULL;

		if (vlptype == vlp_type)
		{
			return (uchar*)vlp;
		}

		read_len += vlp_len;
		padding_len = ((read_len % 4) == 0) ? 0 : (4 - read_len % 4);
		read_len += padding_len;
	}
	return NULL;
}

int write_add_ip_chunk(uint initAckCID, uint initCID)
{
	EVENTLOG(VERBOSE, " - - - Enter write_add_ip_chunk() to cookie");

	init_chunk_t* init = (init_chunk_t*)(simple_chunks_[initCID]);
	init_chunk_t* initack = (init_chunk_t*)(simple_chunks_[initAckCID]);
	if (init == NULL || initack == NULL)
	{
		ERRLOG(FALTAL_ERROR_EXIT, "Invalid init or initAck chunk ID");
		return -1;
	}
	uchar* foundvlp = mch_read_vlparam(VLPARAM_ADDIP, &init->variableParams[0],
		init->chunk_header.chunk_length - INIT_CHUNK_FIXED_SIZES);
	if (foundvlp != NULL)
	{
		ushort vlp_len = ntohs(((vlparam_fixed_t*)foundvlp)->param_length);
		if (vlp_len < VLPARAM_FIXED_SIZE)
		{
			EVENTLOG(VERBOSE, "vlp length less than 4 bytes -> return -1");
			return -1;
		}
		if (vlp_len >= VLPARAM_FIXED_SIZE)
		{
			memcpy(&initack->variableParams[curr_write_pos_[initAckCID]],
				foundvlp, vlp_len);
			curr_write_pos_[initAckCID] += vlp_len;
			while (curr_write_pos_[initAckCID] & 3)
			{
				initack->variableParams[curr_write_pos_[initAckCID]] = 0;
				curr_write_pos_[initAckCID]++;
			}
			EVENTLOG1(VERBOSE,
				"Found VLPARAM_ADDIP (len %d ), copied to init ack cookie",
				vlp_len);
			return 1;
		}
	}
	else
	{
		EVENTLOG(VERBOSE, "Not found VLPARAM_ADDIP");
		return 0;
	}

	EVENTLOG(VERBOSE, " - - - Leave write_add_ip_chunk() to cookie");
	return -1;
}
int mch_write_vlp_setprimarypath(uint initAckCID, uint initCID)
{
	return 0;
}
init_chunk_fixed_t* mch_read_init_fixed(uint chunkID)
{
	if (simple_chunks_[chunkID] == NULL)
	{
		ERRLOG(MAJOR_ERROR, "mch_read_init_fixed()::Invalid chunk ID");
		return NULL;
	}

	if (simple_chunks_[chunkID]->chunk_header.chunk_id == CHUNK_INIT_ACK
		|| simple_chunks_[chunkID]->chunk_header.chunk_id == CHUNK_INIT)
	{
		return &((init_chunk_t *)simple_chunks_[chunkID])->init_fixed;
	}
	else
	{
		ERRLOG(MAJOR_ERROR,
			"mch_read_init_fixed()::chunk type not init or initAck");
		return NULL;
	}
}
void write_unknown_param_error(uchar* pos, uint cid, ushort length, uchar* data)
{
	error_cause_t* ec;
	if (pos == NULL)
	{
		ERRLOG(FALTAL_ERROR_EXIT, "write_unknown_param()::pos gets NULL !");
	}
	ec = (error_cause_t*)pos;
	ec->error_reason_code = htons(VLPARAM_UNRECOGNIZED_PARAM);
	ec->error_reason_length = htons(length + ERR_CAUSE_FIXED_SIZE);
	if (length > 0)
		memcpy(&ec->error_reason, data, length);
	curr_write_pos_[cid] += length + ERR_CAUSE_FIXED_SIZE;
	while ((curr_write_pos_[cid] % 4) != 0)
		curr_write_pos_[cid]++;
}

void mch_write_cookie(uint initCID, uint initAckID, init_chunk_fixed_t* peer_init,
	init_chunk_fixed_t* local_initack, uint cookieLifetime, uint local_tie_tag,
	uint peer_tie_tag, ushort last_dest_port, ushort last_src_port,
	sockaddrunion local_Addresses[], uint num_local_Addresses,
	bool local_support_unre,
	bool local_support_addip,
	sockaddrunion peer_Addresses[],
	uint num_peer_Addresses)
{
	init_chunk_t* initack = (init_chunk_t*)(simple_chunks_[initAckID]);
	if (initack == NULL)
	{
		ERRLOG(FALTAL_ERROR_EXIT, "mch_write_cookie()::Invalid chunk ID");
		return;
	}
	if (initack->chunk_header.chunk_id != CHUNK_INIT_ACK)
	{
		ERRLOG(FALTAL_ERROR_EXIT, "mch_write_cookie()::chunk type not initAck");
		return;
	}
	if (completed_chunks_[initAckID])
	{
		ERRLOG(FALTAL_ERROR_EXIT, "mch_write_cookie()::Invalid chunk ID");
		return;
	}

	cookie_param_t* cookie = (cookie_param_t*)(initack->variableParams
		+ curr_write_pos_[initAckID]);

	//put_vlp_cookie_fixed
	cookie->vlparam_header.param_type = htons(VLPARAM_COOKIE);
	cookie->ck.local_initack = *local_initack;
	cookie->ck.peer_init = *peer_init;
	cookie->ck.local_tie_tag = htonl(local_tie_tag);
	cookie->ck.peer_tie_tag = htonl(peer_tie_tag);
	cookie->ck.src_port = htons(last_src_port);
	cookie->ck.dest_port = htons(last_dest_port);

	uint count;
	uint no_local_ipv4_addresses = 0;
	uint no_remote_ipv4_addresses = 0;
	uint no_local_ipv6_addresses = 0;
	uint no_remote_ipv6_addresses = 0;
	for (count = 0; count < num_local_Addresses; count++)
	{
		switch (saddr_family(&(local_Addresses[count])))
		{
		case AF_INET:
			no_local_ipv4_addresses++;
			break;
		case AF_INET6:
			no_local_ipv6_addresses++;
			break;
		default:
			ERRLOG(FALTAL_ERROR_EXIT, "mch_write_cookie: Address Type Error !");
			break;
		}
	}
	for (count = 0; count < num_peer_Addresses; count++)
	{
		switch (saddr_family(&(peer_Addresses[count])))
		{
		case AF_INET:
			no_remote_ipv4_addresses++;
			break;
		case AF_INET6:
			no_remote_ipv6_addresses++;
			break;
		default:
			ERRLOG(FALTAL_ERROR_EXIT, "mch_write_cookie: Address Type Error !");
			break;
		}
	}
	cookie->ck.no_local_ipv4_addresses = htons(no_local_ipv4_addresses);
	cookie->ck.no_remote_ipv4_addresses = htons(no_remote_ipv4_addresses);
	cookie->ck.no_local_ipv6_addresses = htons(no_local_ipv6_addresses);
	cookie->ck.no_remote_ipv6_addresses = htons(no_remote_ipv6_addresses);
	cookie->ck.cookieLifetime = htonl(cookieLifetime);
	cookie->ck.sendingTime = htonl((uint)get_safe_time_ms());

	uint wr = curr_write_pos_[initAckID];
	curr_write_pos_[initAckID] += COOKIE_PARAM_SIZE;

	EVENTLOG2(VERBOSE, "Building Cookie with %u local, %u peer addresses",
		num_local_Addresses, num_peer_Addresses);
	mch_write_vlp_addrlist(initAckID, local_Addresses, num_local_Addresses);
	mch_write_vlp_addrlist(initAckID, peer_Addresses, num_peer_Addresses);

	/* if endpoint is PR capable, append it in cookie */
	int peer_support_unre = mch_write_vlp_unreliability(initAckID, initCID);
	/* if endpoint is ADD-IP capable, append it in cookie */
	int peersupportaddip = write_add_ip_chunk(initAckID, initCID);
	if (write_add_ip_chunk(initAckID, initCID) > 0)
	{
		/* check for set primary chunk ? Maybe add this only after Cookie Chunk ! */
		mch_write_vlp_setprimarypath(initAckID, initCID);
	}

	/* total length of cookie = vlp fixed+cookie fixed*/
	int cookielen = curr_write_pos_[initAckID] - wr;
	cookie->vlparam_header.param_length = htons(cookielen);
	/* calculate and write hmac when other fields are all filled*/
	while (curr_write_pos_[initAckID] & 3)
	{
		initack->variableParams[curr_write_pos_[initAckID]] = 0;
		curr_write_pos_[initAckID]++;
	}

	if (mch_write_hmac(cookie) < 0)
	{
		ERRLOG(FALTAL_ERROR_EXIT, "mch_write_hmac() failed!");
	}

	mch_write_vlp_ecn(initAckID, initCID);

	/* if both support PRSCTP, enter our PRSCTP parameter to INIT ACK chunk */
	if ((peer_support_unre >= 0) && local_support_unre)
	{
		/* this is variable-length-data, this fuction will internally do alignment */
		mch_write_vlp_of_init_chunk(initAckID, VLPARAM_UNRELIABILITY);
	}
	/* if both support ADD-IP, enter our ADD-IP parameter to INIT ACK chunk */
	if ((peersupportaddip >= 0) && local_support_addip)
	{
		/* this is variable-length-data, this fuction will internally do alignment */
		mch_write_vlp_of_init_chunk(initAckID, VLPARAM_ADDIP);
	}

	/* cookie geco_instance_params is all filledup and now let us align it to 4 by default
	 * the rest of ecn and unre will have a aligned start writing pos  they may need do align internally
	 * here we just confirm it*/
	assert((curr_write_pos_[initAckID] & 3) == 0);
}

int mch_write_vlp_unreliability(uint initAckCID, uint initCID)
{
	EVENTLOG(VERBOSE, " - - - Enter mch_write_vlp_unreliability()");

	init_chunk_t* init = (init_chunk_t*)(simple_chunks_[initCID]);
	init_chunk_t* initack = (init_chunk_t*)(simple_chunks_[initAckCID]);
	if (init == NULL || initack == NULL)
	{
		ERRLOG(FALTAL_ERROR_EXIT, "Invalid init or initAck chunk ID");
		return -1;
	}
	int ret;
	uchar* foundvlp = mch_read_vlparam(VLPARAM_UNRELIABILITY,
		&init->variableParams[0],
		init->chunk_header.chunk_length - INIT_CHUNK_FIXED_SIZES);
	if (foundvlp != NULL)
	{
		ushort vlp_len = ntohs(((vlparam_fixed_t*)foundvlp)->param_length);
		if (vlp_len < VLPARAM_FIXED_SIZE)
		{
			EVENTLOG(VERBOSE, "vlp length less than 4 bytes -> return -1");
			ret = -1;
			return ret;
		}
		if (vlp_len == VLPARAM_FIXED_SIZE)
		{
			/* peer supports it, but doesn't send anything unreliably  */ret =
				0;
		}
		else
		{
			/* peer supports it, and does send some */ret = 1;
		}
		memcpy(&initack->variableParams[curr_write_pos_[initAckCID]], foundvlp,
			vlp_len);
		curr_write_pos_[initAckCID] += vlp_len;
		while (curr_write_pos_[initAckCID] & 3)
		{
			initack->variableParams[curr_write_pos_[initAckCID]] = 0;
			curr_write_pos_[initAckCID]++;
		}
		EVENTLOG1(VERBOSE, "Found pr vlp (len %d ), copied to init ack cookie",
			vlp_len);
	}
	else
	{
		ret = -1;
		EVENTLOG(VERBOSE, "Not found pr vlp");
	}

	EVENTLOG(VERBOSE, " - - - Leave mch_write_vlp_unreliability()");
	return ret;
}

int mch_write_vlp_addrlist(uint chunkid,
	sockaddrunion local_addreslist[MAX_NUM_ADDRESSES],
	uint local_addreslist_size)
{
	if (local_addreslist_size <= 1)
	{
		ERRLOG1(MAJOR_ERROR,
			"mch_write_vlp_addrlist()::Invalid local_addreslist_size should >= 1  %d!",
			local_addreslist_size);
		return -1;
	}
	if (simple_chunks_[chunkid] == NULL)
	{
		ERRLOG(MAJOR_ERROR, "mch_write_vlp_addrlist()::Invalid chunk ID!");
		return -1;
	}
	if (completed_chunks_[chunkid])
	{
		ERRLOG(MAJOR_ERROR,
			"mch_write_vlp_addrlist()::chunk already completed !");
		return -1;
	}

	uchar* vlp;
	if (simple_chunks_[chunkid]->chunk_header.chunk_id != CHUNK_ASCONF)
	{
		vlp =
			&((init_chunk_t *)simple_chunks_[chunkid])->variableParams[curr_write_pos_[chunkid]];
	}
	else
	{
		vlp =
			&((asconfig_chunk_t*)simple_chunks_[chunkid])->variableParams[curr_write_pos_[chunkid]];
	}

	uint i, length = 0;
	ip_address_t* ip_addr;
	for (i = 0; i < local_addreslist_size; i++)
	{

		ip_addr = (ip_address_t*)(vlp + length);
		switch (saddr_family(&(local_addreslist[i])))
		{
		case AF_INET:
			ip_addr->vlparam_header.param_type = htons(VLPARAM_IPV4_ADDRESS);
			ip_addr->vlparam_header.param_length = htons(
				sizeof(struct in_addr) + VLPARAM_FIXED_SIZE);
			ip_addr->dest_addr_un.ipv4_addr = s4addr(&(local_addreslist[i]));
			assert(sizeof(struct in_addr) + VLPARAM_FIXED_SIZE == 8);
			length += 8;
			break;
		case AF_INET6:
			ip_addr->vlparam_header.param_type = htons(
				VLPARAM_IPV6_ADDRESS);
			ip_addr->vlparam_header.param_length = htons(
				sizeof(struct in6_addr) + VLPARAM_FIXED_SIZE);
			memcpy(&ip_addr->dest_addr_un.ipv6_addr,
				&(s6addr(&(local_addreslist[i]))), sizeof(struct in6_addr));
			assert(sizeof(struct in6_addr) + VLPARAM_FIXED_SIZE == 20);
			length += 20;
			break;
		default:
			ERRLOG1(MAJOR_ERROR,
				"dispatch_layer_t::write_addrlist()::Unsupported Address Family %d",
				saddr_family(&(local_addreslist[i])));
			break;
		}
	}
	while (length & 3)
	{
		vlp[length] = 0;
		length++;
	}
	curr_write_pos_[chunkid] += length;
	return 0;
}

int mch_write_vlp_ecn(uint initAckID, uint initCID)
{
	return 0;
}

void mch_write_error_cause(chunk_id_t chunkID, ushort errcode, uchar* errdata,
	uint errdatalen)
{
	assert(simple_chunks_[chunkID] != NULL);
	assert(completed_chunks_[chunkID] == false);
	assert(simple_chunks_[chunkID]->chunk_header.chunk_id == CHUNK_ERROR);
	assert(simple_chunks_[chunkID]->chunk_header.chunk_id == CHUNK_ABORT);
	assert(simple_chunks_[chunkID]->chunk_header.chunk_id == CHUNK_INIT_ACK);
	error_cause_t* ecause =
		(error_cause_t*)&simple_chunks_[chunkID]->chunk_value[curr_write_pos_[chunkID]];
	ecause->error_reason_code = htons(errcode);
	int len = errdatalen + ERR_CAUSE_FIXED_SIZE;
	ecause->error_reason_length = htons(len);
	if (errdatalen > 0 && errdata != NULL)
		memcpy(ecause->error_reason, errdata, errdatalen);
	while (len & 3)
		len++;
	curr_write_pos_[chunkID] += len;
}

chunk_id_t add2chunklist(simple_chunk_t * chunk, const char *log_text)
{
	simple_chunk_index_ = ((simple_chunk_index_ + 1) % MAX_CHUNKS_SIZE_MASK);
	EVENTLOG1(VERBOSE, log_text, simple_chunk_index_);
	simple_chunks_[simple_chunk_index_] = chunk;
	curr_write_pos_[simple_chunk_index_] = 0;
	completed_chunks_[simple_chunk_index_] = false;
	return simple_chunk_index_;
}

uchar mch_make_simple_chunk(simple_chunk_t* chunk)
{
	chunk->chunk_header.chunk_length = ntohs(chunk->chunk_header.chunk_length);
	add2chunklist(chunk, "created chunk from string %u ");
	return simple_chunk_index_;
}

uint mch_make_simple_chunk(uint chunk_type, uchar flag)
{
	//create smple chunk used for ABORT, SHUTDOWN-ACK, COOKIE-ACK
	simple_chunk_t* simple_chunk_ptr = (simple_chunk_t*)geco_malloc_ext(
		SIMPLE_CHUNK_SIZE,
		__FILE__, __LINE__);

	simple_chunk_ptr->chunk_header.chunk_id = chunk_type;
	simple_chunk_ptr->chunk_header.chunk_flags = flag;
	simple_chunk_ptr->chunk_header.chunk_length = CHUNK_FIXED_SIZE;

	add2chunklist(simple_chunk_ptr, "create simple chunk %u");
	return simple_chunk_index_;
}

chunk_id_t mch_make_init_ack_chunk(uint initTag, uint arwnd,
	ushort noOutStreams, ushort noInStreams, uint initialTSN)
{
	assert(sizeof(init_chunk_t) == INIT_CHUNK_TOTAL_SIZE);
	init_chunk_t* initChunk = (init_chunk_t*)geco_malloc_ext(
		INIT_CHUNK_TOTAL_SIZE, __FILE__, __LINE__);
	if (initChunk == NULL)
		ERRLOG(FALTAL_ERROR_EXIT, "malloc failed!\n");
	memset(initChunk, 0, INIT_CHUNK_TOTAL_SIZE);
	initChunk->chunk_header.chunk_id = CHUNK_INIT_ACK;
	initChunk->chunk_header.chunk_flags = 0x00;
	initChunk->chunk_header.chunk_length = INIT_CHUNK_FIXED_SIZES;
	initChunk->init_fixed.init_tag = htonl(initTag);
	initChunk->init_fixed.rwnd = htonl(arwnd);
	initChunk->init_fixed.outbound_streams = htons(noOutStreams);
	initChunk->init_fixed.inbound_streams = htons(noInStreams);
	initChunk->init_fixed.initial_tsn = htonl(initialTSN);
	return add2chunklist((simple_chunk_t*)initChunk,
		"create init ack chunk %u");
}

chunk_id_t mch_make_init_chunk(uint initTag, uint arwnd, ushort noOutStreams,
	ushort noInStreams, uint initialTSN)
{
	assert(sizeof(init_chunk_t) == INIT_CHUNK_TOTAL_SIZE);
	init_chunk_t* initChunk = (init_chunk_t*)geco_malloc_ext(
		INIT_CHUNK_TOTAL_SIZE, __FILE__, __LINE__);
	if (initChunk == NULL)
		ERRLOG(FALTAL_ERROR_EXIT, "malloc failed!\n");
	memset(initChunk, 0, INIT_CHUNK_TOTAL_SIZE);
	initChunk->chunk_header.chunk_id = CHUNK_INIT;
	initChunk->chunk_header.chunk_flags = 0x00;
	initChunk->chunk_header.chunk_length = INIT_CHUNK_FIXED_SIZES;
	initChunk->init_fixed.init_tag = htonl(initTag);
	initChunk->init_fixed.rwnd = htonl(arwnd);
	initChunk->init_fixed.outbound_streams = htons(noOutStreams);
	initChunk->init_fixed.inbound_streams = htons(noInStreams);
	initChunk->init_fixed.initial_tsn = htonl(initialTSN);
	return add2chunklist((simple_chunk_t*)initChunk,
		"create init ack chunk %u");
}
void mch_write_error_cause_unrecognized_chunk(chunk_id_t cid,
	error_cause_t*ecause, uchar* errdata, uint errdatalen)
{
	//error chunk is paramsless chunk so no need simple_chunks[cid] check
	assert(ecause != 0 && errdata != 0 && errdatalen > 0);
	ecause->error_reason_code = htons(VLPARAM_UNRECOGNIZED_PARAM);
	int len = errdatalen + ERR_CAUSE_FIXED_SIZE;
	ecause->error_reason_length = htons(len);
	if (errdatalen > 0 && errdata != NULL)
		memcpy(ecause->error_reason, errdata, errdatalen);
	while (len & 3)
		len++;
	curr_write_pos_[cid] += len;
}

uchar mch_read_chunkid(uchar chunkID)
{
	if (simple_chunks_[chunkID] == NULL)
	{
		ERRLOG(WARNNING_ERROR, "Invalid chunk ID\n");
		return 0;
	}
	return simple_chunks_[chunkID]->chunk_header.chunk_id;
}

ushort mch_read_ostreams(uchar init_chunk_id)
{
	if (simple_chunks_[init_chunk_id] == NULL)
	{
		ERRLOG(MAJOR_ERROR, "Invalid chunk ID\n");
		return 0;
	}

	simple_chunk_t* scptr = simple_chunks_[init_chunk_id];
	uint chunkid = scptr->chunk_header.chunk_id;
	if (chunkid == CHUNK_INIT || chunkid == CHUNK_INIT_ACK)
	{
		ushort osnum = ntohs(
			((init_chunk_t*)scptr)->init_fixed.outbound_streams);
		return osnum;
	}
	else
	{
		ERRLOG(MAJOR_ERROR,
			"mch_read_ostreams(): chunk type not init or initAck");
		return 0;
	}
}

ushort mch_read_instreams(uchar init_chunk_id)
{
	if (simple_chunks_[init_chunk_id] == NULL)
	{
		ERRLOG(MAJOR_ERROR, "Invalid chunk ID\n");
		return -1;
	}

	simple_chunk_t* scptr = simple_chunks_[init_chunk_id];
	uint chunkid = scptr->chunk_header.chunk_id;
	if (chunkid == CHUNK_INIT || chunkid == CHUNK_INIT_ACK)
	{
		ushort isnum = ntohs(
			((init_chunk_t*)scptr)->init_fixed.inbound_streams);
		return isnum;
	}
	else
	{
		ERRLOG(MAJOR_ERROR,
			"mch_read_instreams(): chunk type not init or initAck");
		return -1;
	}
}
uint mch_read_itag(uchar init_chunk_id)
{
	if (simple_chunks_[init_chunk_id] == NULL)
	{
		ERRLOG(MAJOR_ERROR, "Invalid chunk ID\n");
		return -1;
	}

	simple_chunk_t* scptr = simple_chunks_[init_chunk_id];
	uint chunkid = scptr->chunk_header.chunk_id;
	if (chunkid == CHUNK_INIT || chunkid == CHUNK_INIT_ACK)
	{
		uint initag = ntohl(((init_chunk_t*)scptr)->init_fixed.init_tag);
		return initag;
	}
	else
	{
		ERRLOG(MAJOR_ERROR, "mch_read_itag(): chunk type not init or initAck");
		return -1;
	}
}

void mch_free_simple_chunk(uint chunkID)
{
	if (simple_chunks_[chunkID] != NULL)
	{
		EVENTLOG1(INFO, "mch_free_simple_chunk():: free simple chunk %u",
			chunkID);
		geco_free_ext(simple_chunks_[chunkID], __FILE__, __LINE__);
		simple_chunks_[chunkID] = NULL;
	}
	else
	{
		ERRLOG(FALTAL_ERROR_EXIT, "chunk already freed\n");
	}
}

void mch_remove_simple_chunk(uchar chunkID)
{
	if (simple_chunks_[chunkID] != NULL)
	{
		simple_chunks_[chunkID] = NULL;
	}
	else
	{
		ERRLOG(WARNNING_ERROR, "chunk already forgotten");
	}
}
simple_chunk_t *mch_complete_simple_chunk(uint chunkID)
{
	if (simple_chunks_[chunkID] == NULL)
	{
		ERRLOG(MAJOR_ERROR, "Invalid chunk ID\n");
		return NULL;
	}
	simple_chunks_[chunkID]->chunk_header.chunk_length = htons(
		(simple_chunks_[chunkID]->chunk_header.chunk_length
			+ curr_write_pos_[chunkID]));
	completed_chunks_[chunkID] = true;
	return simple_chunks_[chunkID];
}

void mch_write_vlp_supportedaddrtypes(chunk_id_t chunkID, bool with_ipv4,
	bool with_ipv6, bool with_dns)
{
	assert(simple_chunks_[chunkID] != NULL);
	assert(completed_chunks_[chunkID] == false);
	assert(
		simple_chunks_[chunkID]->chunk_header.chunk_id == CHUNK_INIT || simple_chunks_[chunkID]->chunk_header.chunk_id == CHUNK_INIT_ACK);

	ushort num_of_types = 0, position = 0;
	if (with_ipv4)
		num_of_types++;
	if (with_ipv6)
		num_of_types++;
	if (with_dns)
		num_of_types++;
	if (num_of_types == 0)
		ERRLOG(FALTAL_ERROR_EXIT,
			"put_supported_addr_types()::No Supported Address Types -- Program Error\n");

	ushort total_length = VLPARAM_FIXED_SIZE + num_of_types * sizeof(ushort);
	supported_address_types_t* param =
		(supported_address_types_t*) &((init_chunk_t*)simple_chunks_[chunkID])->variableParams[curr_write_pos_[chunkID]];
	param->vlparam_header.param_type = htons(VLPARAM_SUPPORTED_ADDR_TYPES);
	param->vlparam_header.param_length = htons(total_length);

	if (with_ipv4)
	{
		param->address_type[position] = htons(VLPARAM_IPV4_ADDRESS);
		position++;
	}
	if (with_ipv6)
	{
		param->address_type[position] = htons(VLPARAM_IPV6_ADDRESS);
		position++;
	}
	if (with_dns)
	{
		param->address_type[position] = htons(VLPARAM_HOST_NAME_ADDR);
		position++;
	}

	/* take care of padding */
	if (total_length & 3)
	{
		*((ushort*)((uchar*)param + total_length)) = 0;
		total_length += 2;
	}
	curr_write_pos_[chunkID] += total_length;
}
void mch_write_vlp_of_init_chunk(chunk_id_t initChunkID, ushort pCode,
	uchar* data, ushort len)
{
	assert(simple_chunks_[initChunkID] != NULL);
	assert(completed_chunks_[initChunkID] == false);
	assert(
		simple_chunks_[initChunkID]->chunk_header.chunk_id == CHUNK_INIT || simple_chunks_[initChunkID]->chunk_header.chunk_id == CHUNK_INIT_ACK);
	uchar* vlPtr =
		&((init_chunk_t*)simple_chunks_[initChunkID])->variableParams[curr_write_pos_[initChunkID]];
	*((ushort*)vlPtr) = htons(pCode);
	*((ushort*)(vlPtr + sizeof(ushort))) = htons(len + VLPARAM_FIXED_SIZE);
	if (len > 0 && data != NULL)
		memcpy(vlPtr + 2 * sizeof(ushort), data, len);
	len += VLPARAM_FIXED_SIZE;
	while (len & 3)
	{
		vlPtr[len] = 0;
		len++;
	}
	curr_write_pos_[initChunkID] += len;
}

error_chunk_t* mch_make_error_chunk()
{
	error_chunk_t* errorChunk = (error_chunk_t*)geco_malloc_ext(
		INIT_CHUNK_TOTAL_SIZE, __FILE__,
		__LINE__);
	if (errorChunk == NULL)
		ERRLOG(FALTAL_ERROR_EXIT, "malloc failed!\n");
	memset(errorChunk, 0, ERROR_CHUNK_TOTAL_SIZE);
	errorChunk->chunk_header.chunk_id = CHUNK_ERROR;
	errorChunk->chunk_header.chunk_flags = 0x00;
	errorChunk->chunk_header.chunk_length = CHUNK_FIXED_SIZE;
	return errorChunk;
}

void put_vlp_cookie_fixed(cookie_param_t* cookie, init_chunk_fixed_t* peer_init,
	init_chunk_fixed_t* local_initack, uint cookieLifetime,
	uint local_tie_tag, uint peer_tie_tag, ushort last_dest_port,
	ushort last_src_port, sockaddrunion local_Addresses[],
	uint num_local_Addresses, sockaddrunion peer_Addresses[],
	uint num_peer_Addresses)
{
	cookie->vlparam_header.param_type = htons(VLPARAM_COOKIE);
	cookie->ck.local_initack = *local_initack;
	cookie->ck.peer_init = *peer_init;
	cookie->ck.local_tie_tag = htonl(local_tie_tag);
	cookie->ck.peer_tie_tag = htonl(peer_tie_tag);
	cookie->ck.src_port = htons(last_src_port);
	cookie->ck.dest_port = htons(last_dest_port);

	uint count;
	uint no_local_ipv4_addresses = 0;
	uint no_remote_ipv4_addresses = 0;
	uint no_local_ipv6_addresses = 0;
	uint no_remote_ipv6_addresses = 0;
	for (count = 0; count < num_local_Addresses; count++)
	{
		switch (saddr_family(&(local_Addresses[count])))
		{
		case AF_INET:
			no_local_ipv4_addresses++;
			break;
		case AF_INET6:
			no_local_ipv6_addresses++;
			break;
		default:
			ERRLOG(FALTAL_ERROR_EXIT, "mch_write_cookie: Address Type Error !");
			break;
		}
	}
	for (count = 0; count < num_peer_Addresses; count++)
	{
		switch (saddr_family(&(peer_Addresses[count])))
		{
		case AF_INET:
			no_remote_ipv4_addresses++;
			break;
		case AF_INET6:
			no_remote_ipv6_addresses++;
			break;
		default:
			ERRLOG(FALTAL_ERROR_EXIT, "mch_write_cookie: Address Type Error !");
			break;
		}
	}
	cookie->ck.no_local_ipv4_addresses = htons(no_local_ipv4_addresses);
	cookie->ck.no_remote_ipv4_addresses = htons(no_remote_ipv4_addresses);
	cookie->ck.no_local_ipv6_addresses = htons(no_local_ipv6_addresses);
	cookie->ck.no_remote_ipv6_addresses = htons(no_remote_ipv6_addresses);
	cookie->ck.cookieLifetime = htonl(cookieLifetime);
	cookie->ck.sendingTime = htonl((uint)get_safe_time_ms());
}

uint put_vlp_cookie_life_span(cookie_preservative_t* preserv,
	unsigned int lifespanIncrement)
{
	ushort len = VLPARAM_FIXED_SIZE + sizeof(unsigned int);
	preserv->vlparam_header.param_type = htons(VLPARAM_COOKIE_PRESEREASONV);
	preserv->vlparam_header.param_length = htons(len);
	preserv->cookieLifetimeInc = htonl(lifespanIncrement);
	return len;
}

/*
 3.3.11.  Cookie Echo (COOKIE ECHO) (10)
 This chunk is used only during the initialization of an association.
 It is sent by the initiator of an association to its peer to complete
 the initialization process.  This chunk MUST precede any DATA chunk
 sent within the association, but MAY be bundled with one or more DATA
 chunks in the same packet.

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |   Type = 10   |Chunk  Flags   |         Length                |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 /                     Cookie                                    /
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 Set to 0 on transmit and ignored on receipt.
 5.1.3.  Generating State Cookie
 When sending an INIT ACK as a response to an INIT chunk, the sender
 of INIT ACK creates a State Cookie and sends it in the State Cookie
 parameter of the INIT ACK.  Inside this State Cookie, the sender
 should include a MAC (see [RFC2104] for an example), a timestamp on
 when the State Cookie is created, and the lifespan of the State
 Cookie, along with all the information necessary for it to establish
 the association.

 The following steps SHOULD be taken to generate the State Cookie:
 1)  Create an association TCB using information from both the
 received INIT and the outgoing INIT ACK chunk,
 2)  In the TCB, set the creation time to the current time of day, and
 the lifespan to the protocol parameter 'Valid.Cookie.Life' (see
 Section 15),
 3)  From the TCB, identify and collect the minimal subset of
 information needed to re-create the TCB, and generate a MAC using
 this subset of information and a secret key (see [RFC2104] for an
 example of generating a MAC), and
 4)  Generate the State Cookie by combining this subset of information
 and the resultant MAC.
 */

static int mch_write_hmac(cookie_fixed_t* cookieString, ushort cookieLength,
	uchar* digest)
{
	if (cookieString == NULL || cookieLength == 0) return -1;
	memset(cookieString->hmac, 0, HMAC_LEN);

	uchar* key = get_secre_key(KEY_READ);
	if (key == NULL)
	{
		ERRLOG(MAJOR_ERROR, "mch_write_hmac()::get_secre_key() FAILED!");
		return -1;
	}

	MD5_CTX ctx;
	MD5Init(&ctx);
	MD5Update(&ctx, (uchar*)cookieString, cookieLength);
	MD5Update(&ctx, (uchar*)key, SECRET_KEYSIZE);
	MD5Final(digest, &ctx);
	return 0;
}

/** computes a cookie signature.*/
int mch_write_hmac(cookie_param_t* cookieString)
{
	if (cookieString == NULL) return -1;
	memset(cookieString->ck.hmac, 0, HMAC_SIZE);

	uint cookieLength = ntohs(
		cookieString->vlparam_header.param_length) - VLPARAM_FIXED_SIZE;
	if (cookieLength == 0)
		return -1;

	uchar* key = get_secre_key(KEY_READ);
	if (key == NULL)
	{
		ERRLOG(MAJOR_ERROR, "mch_write_hmac()::get_secre_key() FAILED!");
		return -1;
	}

	MD5_CTX ctx;
	MD5Init(&ctx);
	MD5Update(&ctx, (uchar*)&cookieString->ck, cookieLength);
	MD5Update(&ctx, (uchar*)key, SECRET_KEYSIZE);
	MD5Final(cookieString->ck.hmac, &ctx);
}

bool mch_verify_hmac(cookie_echo_chunk_t* cookie_chunk)
{
	cookie_fixed_t* cookie = &cookie_chunk->cookie;
	uchar cookieSignature[HMAC_LEN];
	memcpy(cookieSignature, cookie->hmac, HMAC_LEN); // store existing hmac

	uchar ourSignature[HMAC_LEN];
	ushort cookieLength =
		cookie_chunk->chunk_header.chunk_length - CHUNK_FIXED_SIZE;
	mch_write_hmac(cookie, cookieLength, ourSignature); // recalculate and store hmac

	return (memcmp(cookieSignature, ourSignature, HMAC_LEN) == 0); //compare noth hmacs
}
