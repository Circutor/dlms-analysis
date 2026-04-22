-- 
-- Lua dissector for PRIME over UDP (Ticket #65)
--
-- Version 1.0
-- Last update: 8th March 2023
--
-- Declare the protocol
prime_proto = Proto("PRIME","PRIME over UDP")

local PrimeHT = {
   [0] = "General PDU",
   [1] = "PNPDU",
   [2] = "BCN",
} 

local PduType = {
   [0] = "REG",
   [1] = "CON",
   [2] = "PRO",
   [3] = "BSI",
   [4] = "FRA",
   [5] = "CFP",
   [6] = "ALV",
   [7] = "MUL",
   [8] = "PRM",
   [9] = "SEC",
}

local DOType = {
   [0] = "UP",
   [1] = "DW",
}

-- PRIME header
local HDR = ProtoField.bytes("prime.hdr","Generic MAC Header")
local HDR_UNUSED = ProtoField.uint8("prime.hdr_unused","Unused",base.HEX)
local HT = ProtoField.uint8("prime.ht","HT",base.HEX,PrimeHT)
local HDR_RESERVED = ProtoField.uint8("prime.hdr_reserved","Reserved",base.HEX)
local DO = ProtoField.uint8("prime.do","DO",base.HEX,DOType)
local LEVEL = ProtoField.uint8("prime.level","LEVEL",base.HEX)
local HCS = ProtoField.uint8("prime.hcs","HCS",base.HEX)
local PKT = ProtoField.bytes("prime.pkt","Packet Header")
local PKT_RESERVED = ProtoField.uint8("prime.pkt_reserved","Reserved",base.HEX)
local PNH = ProtoField.bytes("prime.pnh","PNPDU Header")
local PNH_RESERVED = ProtoField.uint8("prime.pnh_reserved","Reserved",base.HEX)
local BCN = ProtoField.bytes("prime.bcn","Beacon PDU")
local BCN_RESERVED = ProtoField.uint8("prime.bcn_reserved","Reserved",base.HEX)
local NAD = ProtoField.uint8("prime.nad","NAD",base.HEX)
local SID = ProtoField.uint8("prime.sid","SID",base.HEX)
local LNID = ProtoField.uint16("prime.lnid","LNID",base.HEX)
local PRIO = ProtoField.uint8("prime.prio","PRIO",base.HEX)
local C = ProtoField.uint8("prime.c","C",base.HEX)
local SPAD = ProtoField.uint8("prime.spad","SPAD",base.HEX)
local LCID = ProtoField.uint16("prime.lcid","LCID",base.HEX)
local CTYPE = ProtoField.uint16("prime.ctype","CTYPE",base.HEX)
local LEN = ProtoField.uint16("prime.len","LEN",base.HEX)
local ControlData = ProtoField.bytes("prime.data","Control Data",base.NONE)
local MAC = ProtoField.string("prime.mac","MAC")
local SNA = ProtoField.string("prime.sna","SNA")
local PNA = ProtoField.string("prime.pna","PNA")
local PRO_N = ProtoField.uint8("prime.pro_n","N",base.HEX)
local PRO_RQ = ProtoField.uint8("prime.pro_rq","RQ",base.HEX)
local PRO_TIME = ProtoField.uint8("prime.pro_time","TIME",base.HEX)
local PRO_NSID = ProtoField.uint8("prime.pro_nsid","NSID",base.HEX)
local FRQ = ProtoField.uint8("prime.frq","FRQ",base.HEX)
local BSI_SLT = ProtoField.uint8("prime.pro_slt","SLT",base.HEX)
local SEQ = ProtoField.uint8("prime.seq","SEQ",base.HEX)
local QLTY = ProtoField.uint8("prime.qlty","QLTY",base.HEX)
local CNT = ProtoField.uint8("prime.cnt","CNT",base.HEX)
local POS = ProtoField.uint8("prime.pos","POS",base.HEX)
local CFP = ProtoField.uint16("prime.cfp","CFP",base.HEX)
local UPCOST = ProtoField.uint8("prime.upcost","UPCOST",base.HEX)
local DNCOST = ProtoField.uint8("prime.dncost","DNCOST",base.HEX)
local CRC = ProtoField.uint32("prime.crc","CRC",base.HEX)

prime_proto.fields = {HDR, HDR_UNUSED, HT, HDR_RESERVED, DO, LEVEL, HCS, PKT, PKT_RESERVED, NAD, PRIO, C, SID, LNID, SPAD, LCID, CTYPE, LEN, PNH, PNH_RESERVED, BCN, BCN_RESERVED, ControlData, MAC, SNA, PNA, PRO_N, PRO_RQ, PRO_TIME, PRO_NSID, FRQ, BSI_SLT, SEQ, QLTY, CNT, POS, CFP, UPCOST, DNCOST, CRC}

local function format_mac(range)
	return string.format("%02x:%02x:%02x:%02x:%02x:%02x", range(0,1):uint(), range(1,1):uint(), range(2,1):uint(), range(3,1):uint(), range(4,1):uint(), range(5,1):uint())
end

local function extract_bits(range, bit_offset, bit_length)
	local value = 0
	for index = 0, bit_length - 1 do
		local absolute_bit = bit_offset + index
		local byte_index = math.floor(absolute_bit / 8)
		local bit_index = 7 - (absolute_bit % 8)
		local bit_value = bit.band(range(byte_index,1):uint(), bit.lshift(1, bit_index))
		if bit_value ~= 0 then
			value = value * 2 + 1
		else
			value = value * 2
		end
	end
	return value
end

local function dissect_bcn(buffer, pinfo, t_prime)
	local frame_len = buffer:len()
	if frame_len < 18 then
		pinfo.cols['info'] = "BCN (truncated)"
		return
	end

	local bcn_unused = extract_bits(buffer(0,1), 0, 2)
	local prime_ht = extract_bits(buffer(0,1), 2, 2)
	local bcn_reserved_hdr = extract_bits(buffer(0,1), 4, 1)
	local qlty = extract_bits(buffer(0,1), 5, 3)
	local cnt = extract_bits(buffer(2,1), 0, 3)
	local pos = extract_bits(buffer(2,1), 3, 3)
	local cfp = extract_bits(buffer(2,2), 6, 10)
	local bcn_reserved_lvl = extract_bits(buffer(4,1), 0, 1)
	local level = extract_bits(buffer(4,1), 1, 6)
	local seq = extract_bits(buffer(5,1), 0, 5)
	local frq = extract_bits(buffer(5,1), 5, 3)
	local sna = format_mac(buffer(6,6))

	local t_bcn = t_prime:add(BCN, buffer(0,18))
	t_bcn:add(HDR_UNUSED, buffer(0,1), bcn_unused)
	t_bcn:add(HT, buffer(0,1), prime_ht)
	t_bcn:add(BCN_RESERVED, buffer(0,1), bcn_reserved_hdr)
	t_bcn:add(QLTY, buffer(0,1), qlty)
	t_bcn:add(SID, buffer(1,1))
	t_bcn:add(CNT, buffer(2,1), cnt)
	t_bcn:add(POS, buffer(2,1), pos)
	t_bcn:add(CFP, buffer(2,2), cfp)
	t_bcn:add(BCN_RESERVED, buffer(4,1), bcn_reserved_lvl)
	t_bcn:add(LEVEL, buffer(4,1), level)
	t_bcn:add(SEQ, buffer(5,1), seq)
	t_bcn:add(FRQ, buffer(5,1), frq)
	t_bcn:add(SNA, buffer(6,6), sna)
	t_bcn:add(UPCOST, buffer(12,1))
	t_bcn:add(DNCOST, buffer(13,1))
	t_bcn:add(CRC, buffer(14,4))

	pinfo.cols['info'] = "BCN CNT="..cnt..", POS="..pos..", CFP="..cfp..", SEQ="..seq..", FRQ="..frq
end

local function dissect_pnpdu(buffer, pinfo, t_prime)
	local frame_len = buffer:len()
	if frame_len < 14 then
		pinfo.cols['info'] = "PNPDU (truncated)"
		return
	end

	local pnh_unused = extract_bits(buffer(0,1), 0, 2)
	local prime_ht = extract_bits(buffer(0,1), 2, 2)
	local pnh_reserved = extract_bits(buffer(0,1), 4, 4)
	local sna_range = buffer(1,6)
	local pna_range = buffer(7,6)
	local sna = format_mac(sna_range)
	local pna = format_mac(pna_range)

	local t_pnh = t_prime:add(PNH, buffer(0,14))
	t_pnh:add(HDR_UNUSED, buffer(0,1), pnh_unused)
	t_pnh:add(HT, buffer(0,1), prime_ht)
	t_pnh:add(PNH_RESERVED, buffer(0,1), pnh_reserved)
	t_pnh:add(SNA, sna_range, sna)
	t_pnh:add(PNA, pna_range, pna)
	t_pnh:add(HCS, buffer(13,1))

	pinfo.cols['info'] = "PNPDU SNA="..sna..", PNA="..pna
end

local function dissect_general_pdu(buffer, pinfo, t_prime)
	local frame_len = buffer:len()
	if frame_len < 13 then
		pinfo.cols['info'] = "General PDU (truncated)"
		return
	end

	local generic_header = buffer(0,3)
	local packet_header = buffer(3,6)
	local hdr_unused = extract_bits(generic_header, 0, 2)
	local prime_ht = extract_bits(generic_header, 2, 2)
	local hdr_reserved = extract_bits(generic_header, 4, 5)
	local direction = extract_bits(generic_header, 9, 1)
	local level = extract_bits(generic_header, 10, 6)
	local pkt_reserved = extract_bits(packet_header, 0, 3)
	local nad = extract_bits(packet_header, 3, 1)
	local prio = extract_bits(packet_header, 4, 2)
	local c = extract_bits(packet_header, 6, 1)
	local lcid_or_ctype = extract_bits(packet_header, 7, 9)
	local sid = extract_bits(packet_header, 16, 8)
	local lnid = extract_bits(packet_header, 24, 14)
	local spad = extract_bits(packet_header, 38, 1)
	local pkt_len = extract_bits(packet_header, 39, 9)
	local available_payload_len = math.max(frame_len - 13, 0)
	local payload_len = math.min(pkt_len, available_payload_len)
	local payload_offset = 9

	local t_hdr = t_prime:add(HDR, buffer(0,3))
	t_hdr:add(HDR_UNUSED, buffer(0,1), hdr_unused)
	t_hdr:add(HT, buffer(0,1), prime_ht)
	t_hdr:add(HDR_RESERVED, buffer(0,2), hdr_reserved)
	t_hdr:add(DO, buffer(1,1), direction)
	t_hdr:add(LEVEL, buffer(1,1), level)
	t_hdr:add(HCS, buffer(2,1))

	local t_pkt = t_prime:add(PKT, buffer(3,6))
	t_pkt:add(PKT_RESERVED, buffer(3,1), pkt_reserved)
	t_pkt:add(NAD, buffer(3,1), nad)
	t_pkt:add(PRIO, buffer(3,1), prio)
	t_pkt:add(C, buffer(3,1), c)
	if c == 1 then
		t_pkt:add(CTYPE, buffer(3,2), lcid_or_ctype)
	else
		t_pkt:add(LCID, buffer(3,2), lcid_or_ctype)
	end
	t_pkt:add(SID, buffer(5,1), sid)
	t_pkt:add(LNID, buffer(6,2), lnid)
	t_pkt:add(SPAD, buffer(7,1), spad)
	t_pkt:add(LEN, buffer(7,2), pkt_len)

	if c == 0 then
		if payload_len > 0 then
			t_prime:add(ControlData, buffer(payload_offset,payload_len))
		end
		if direction == 0 then
			pinfo.cols['info'] = "DATA_S"
		else
			pinfo.cols['info'] = "DATA_B"
		end
	elseif lcid_or_ctype == 1 then
		if payload_len < 8 then
			pinfo.cols['info'] = "REG (truncated)"
			if payload_len > 0 then
				t_prime:add(ControlData, buffer(payload_offset,payload_len))
			end
			t_prime:add(CRC, buffer(frame_len-4,4))
			return
		end

		local n = bit.band(buffer(9,1):uint(), 0x80) / 128
		local time = bit.band(buffer(10,1):uint(), 0x07)
		local instance = buffer(11,6)
		local sna = format_mac(instance)
		local cap = bit.band(buffer(9,1):uint() * 256 + buffer(10,1):uint(), 0x03F8) / 8
		
		t_prime:add(MAC, buffer(11,6), sna)
		
		local tREG
		if direction == 0 and n == 0 and lnid == 0x3FFF then
	    		tREG = "REQ"
		elseif direction == 1 and n == 0 and lnid < 0x3FFF then
			tREG = "RSP"
		elseif direction == 0 and n == 0 and lnid < 0x3FFF then
			tREG = "ACK"
		elseif direction == 1 and n == 1 and lnid == 0x3FFF then
			tREG = "REJ"
		elseif direction == 0 and n == 1 and lnid < 0x3FFF then
			tREG = "UNR_S"
		elseif direction == 1 and n == 1 and lnid < 0x3FFF then
			tREG = "UNR_B"
		end
		
		pinfo.cols['info'] = "REG "..(tREG or "UNK")..", TIME="..time..", EUI48="..sna..", TCAP="..cap
	elseif lcid_or_ctype == 2 then
		if payload_len > 0 then
			t_prime:add(ControlData, buffer(payload_offset,payload_len))
		end
		local n = bit.band(buffer(9,1):uint(), 0x80) / 128
		local d = bit.band(buffer(9,1):uint(), 0x40) / 64
		local arq = bit.band(buffer(9,1):uint(), 0x20) / 32
		local e = bit.band(buffer(9,1):uint(), 0x10) / 16
		
		local tCON
		if direction == 0 and n == 0 then
	    		tCON = "REQ_S"
		elseif direction == 1 and n == 0 then
			tCON = "RSP_B"
		elseif direction == 0 and n == 1 then
			tCON = "CLS_S"
		elseif direction == 1 and n == 1 then
			tCON = "CLS_B"
		end
		
		pinfo.cols['info'] = "CON "..tCON
	    elseif lcid_or_ctype == 3 then
		if payload_len < 2 then
			pinfo.cols['info'] = "PRO (truncated)"
			if payload_len > 0 then
				t_prime:add(ControlData, buffer(payload_offset,payload_len))
			end
			t_prime:add(CRC, buffer(frame_len-4,4))
			return
		end

	    		local n = bit.band(buffer(9,1):uint(), 0x80) / 128
	    		local rq = bit.band(buffer(9,1):uint(), 0x38) / 8
	    		local time = bit.band(buffer(9,1):uint(), 0x07)
	    		local nsid = buffer(10,1):uint()
	    		
	    		t_prime:add(PRO_N, buffer(9,1), n)
	    		t_prime:add(PRO_RQ, buffer(9,1), rq)
	    		t_prime:add(PRO_TIME, buffer(9,1), time)
	    		t_prime:add(PRO_NSID, buffer(10,1))
	    		
	    		local tPRO
	    		if direction == 0 and n == 0 and nsid == 0xFF then
	    			tPRO = "REG_S"
			elseif direction == 1 and n == 0 and nsid ~= 0xFF then
				tPRO = "REG_B"
			elseif direction == 0 and n == 0 and nsid ~= 0xFF then
				tPRO = "ACK"
			elseif direction == 1 and n == 1 and nsid == 0xFF then
				tPRO = "REJ"
			elseif direction == 0 and n == 1 and nsid ~= 0xFF then
				tPRO = "DEM_S"
			elseif direction == 1 and n == 1 and nsid ~= 0xFF then
				tPRO = "DEM_B"
			end
			
			local info = ""			
			if direction == 0 and n == 0 and nsid == 0xFF and payload_len >= 10 then
				local instance = buffer(11,6)
				local pna = format_mac(instance)
				local upcost = buffer(17,1):uint()
				local dncost = buffer(18,1):uint()
				
				t_prime:add(MAC, buffer(11,6), pna)
				t_prime:add(UPCOST, buffer(17,1), upcost)
				t_prime:add(DNCOST, buffer(18,1), dncost)
				
				info = ", PNA="..pna..", UPCOST="..upcost..", DNCOST="..dncost
			elseif payload_len > 2 then
				t_prime:add(ControlData, buffer(11,payload_len - 2))
			end
			
			pinfo.cols['info'] = "PRO "..tPRO..", N="..n..", RQ="..rq..", TIME="..time..", NSID="..nsid..info
	elseif lcid_or_ctype == 4 then
		if payload_len < 2 then
			pinfo.cols['info'] = "BSI (truncated)"
			if payload_len > 0 then
				t_prime:add(ControlData, buffer(payload_offset,payload_len))
			end
			t_prime:add(CRC, buffer(frame_len-4,4))
			return
		end

		local frq = bit.band(buffer(9,1):uint(), 0x07)
		local slt = bit.band(buffer(10,1):uint(), 0xE0) / 32
		local seq = bit.band(buffer(10,1):uint(), 0x1F)
		
		t_prime:add(FRQ, buffer(9,1), frq)
	    	t_prime:add(BSI_SLT, buffer(10,1), slt)
	    	t_prime:add(SEQ, buffer(10,1), seq)
		
		local tBSI = ""
	    	if direction == 0 then
	    		tBSI = "ACK"
	    	else
		    	tBSI = "IND"
		    end
		    
		    pinfo.cols['info'] = "BSI "..tBSI..", FRQ="..frq..", SLT="..slt..", SEQ="..seq
	    elseif lcid_or_ctype == 7 then
		if payload_len < 3 then
			pinfo.cols['info'] = "ALV (truncated)"
			if payload_len > 0 then
				t_prime:add(ControlData, buffer(payload_offset,payload_len))
			end
			t_prime:add(CRC, buffer(frame_len-4,4))
			return
		end

	    		local rxcnt = bit.band(buffer(9,1):uint(), 0xE0) / 32
	    		local txcnt = bit.band(buffer(9,1):uint(), 0x1C) / 4
		local time = bit.band(buffer(10,1):uint(), 0x07)
	    		local ssid = buffer(11,1):uint()
	    	
	    		local tALV = ""
	    		if direction == 0 then
	    			tALV = "S"
	    		else
		    		tALV = "B"
		    	end
		    
		    pinfo.cols['info'] = "ALV "..tALV.." (RX "..rxcnt.." | TX "..txcnt.."), TIME="..time..", SSID="..ssid
	    elseif lcid_or_ctype == 9 then
		if payload_len > 1 then
			t_prime:add(ControlData, buffer(10,payload_len - 1))
		end

	    		local r = bit.band(buffer(9,1):uint(), 0x80) / 128
	    		local n = bit.band(buffer(9,1):uint(), 0x40) / 64
	    		
	    		if r == 0 and n == 0 then
	    			pinfo.cols['info'] = "PRM_REQ"
	    		elseif r == 1 and n == 0 then
		    		pinfo.cols['info'] = "PRM_ACK"
	    		elseif r == 1 and n == 1 then
		    		pinfo.cols['info'] = "PRM_REJ"
		    end
	    else 
		if payload_len > 0 then
			t_prime:add(ControlData, buffer(payload_offset,payload_len))
		end
	    	pinfo.cols['info'] = PduType[lcid_or_ctype - 1] or ("CTYPE="..lcid_or_ctype)
	    end
	    
	    t_prime:add(CRC, buffer(frame_len-4,4))
end

-- Create a simple dissection function
function prime_proto.dissector(buffer, pinfo, tree)
	local t_prime = tree:add(prime_proto, buffer())
	local frame_len = buffer:len()
	if frame_len < 1 then
		return
	end

	local prime_ht = extract_bits(buffer(0,1), 2, 2)
	
	-- create the PRIME protocol tree item
	pinfo.cols['protocol'] = "PRIME"
	pinfo.cols['info'] = PrimeHT[prime_ht] or ("HT="..prime_ht)
	
	-- processing General PDU
    if prime_ht == 0 then
		return dissect_general_pdu(buffer, pinfo, t_prime, frame_len, prime_ht)
	elseif prime_ht == 1 then
		dissect_pnpdu(buffer, pinfo, t_prime)
	elseif prime_ht == 2 then
		dissect_bcn(buffer, pinfo, t_prime)
	else
		if frame_len > 5 then
			t_prime:add(ControlData, buffer(1,frame_len - 5))
		end
    end
end

-- load the udp port table
udp_table = DissectorTable.get("udp.port")
-- register the protocol to port 7919
udp_table:add(7919, prime_proto)
