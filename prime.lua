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
local HT = ProtoField.uint8("prime.ht","HT",base.HEX,COSEMpdu)
local DO = ProtoField.uint8("prime.do","DO",base.HEX,DOType)
local LEVEL = ProtoField.uint8("prime.level","LEVEL",base.HEX)
local HCS = ProtoField.uint8("prime.hcs","HCS",base.HEX)
local CTYPE = ProtoField.uint8("prime.ctype","CTYPE",base.HEX)
local SID = ProtoField.uint8("prime.sid","SID",base.HEX)
local LNID = ProtoField.uint16("prime.lnid","LNID",base.HEX)
local PRIO = ProtoField.uint8("prime.prio","PRIO",base.HEX)
local ControlData = ProtoField.bytes("prime.data","Control Data",base.NONE)
local MAC = ProtoField.string("prime.mac","MAC")
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
local CFP = ProtoField.uint8("prime.cfp","CFP",base.HEX)
local UPCOST = ProtoField.uint8("prime.upcost","UPCOST",base.HEX)
local DNCOST = ProtoField.uint8("prime.dncost","DNCOST",base.HEX)
local CRC = ProtoField.uint32("prime.crc","CRC",base.HEX)

prime_proto.fields = {PRIME, HT, DO, LEVEL, HCS, PRIO, CTYPE, SID, LNID, ControlData, MAC, PRO_N, PRO_RQ, PRO_TIME, PRO_NSID, FRQ, BSI_SLT, SEQ, QLTY, CNT, POS, CFP, UPCOST, DNCOST, CRC}

-- Create a simple dissection function
function prime_proto.dissector(buffer, pinfo, tree)
	local t_prime = tree:add(prime_proto, buffer())
	local frame_len = 0
	local prime_ht = bit.band(buffer(0,1):uint(), 0x30) / 16
	
	-- create the PRIME protocol tree item
	t_prime:add(HT, buffer(0,1), prime_ht)
	frame_len = buffer:len()
	pinfo.cols['info'] = PrimeHT[prime_ht]
	
	-- processing General PDU
    if prime_ht == 0 then
        local direction = bit.band(buffer(1,1):uint(), 0x40) / 64
        local level = bit.band(buffer(1,1):uint(), 0x0F)
        local lnid = bit.band(buffer(6,1):uint() * 256 + buffer(7,1):uint(), 0xFFFC) / 4
        local prio = 1 + bit.band(buffer(3,1):uint(), 0x0C) / 4
        local c = bit.band(buffer(3,1):uint(), 0x02) / 2
    	local c_type = buffer(4,1):uint()

		t_prime:add(DO, buffer(1,1), direction)
		t_prime:add(LEVEL, buffer(1,1), level)
		t_prime:add(HCS, buffer(2,1))
		t_prime:add(PRIO, buffer(3,1), prio)
		t_prime:add(SID, buffer(5,1))
		t_prime:add(LNID, buffer(6,2), lnid)
		t_prime:add(ControlData, buffer(9,frame_len - 13))
		if c == 1 then
			t_prime:add(CTYPE, buffer(4,1))
		end

		if c == 0 then
			if direction == 0 then
				pinfo.cols['info'] = "DATA_S"
			else
				pinfo.cols['info'] = "DATA_B"
			end
		elseif c_type == 1 then
			local n = bit.band(buffer(9,1):uint(), 0x80) / 128
			local time = bit.band(buffer(10,1):uint(), 0x07)
			local instance = buffer(11,6)
			local sna = string.format("%02x:%02x:%02x:%02x:%02x:%02x",instance(0,1):uint(),instance(1,1):uint(),instance(2,1):uint(),instance(3,1):uint(),instance(4,1):uint(),instance(5,1):uint())
			local cap = bit.band(buffer(9,1):uint() * 256 + buffer(10,1):uint(), 0x03F8) / 8
			
			t_prime:add(MAC, buffer(11,6), sna)
			
			local tREG
			if direction == 0 and n == 0 and lnid == 0x3FFF then
	    		tREG = "REQ"
			elseif direction == 1 and n == 0 and nsid ~= 0x3FFF then
				tREG = "RSP"
			elseif direction == 0 and n == 0 and nsid ~= 0x3FFF then
				tREG = "ACK"
			elseif direction == 1 and n == 1 and nsid == 0x3FF then
				tREG = "REJ"
			elseif direction == 0 and n == 1 and nsid ~= 0x3FFF then
				tREG = "UNR_S"
			elseif direction == 1 and n == 1 and nsid ~= 0x3FFF then
				tREG = "UNR_B"
			end
			
			pinfo.cols['info'] = "REG "..tREG..", TIME="..time..", EUI48="..sna..", TCAP="..cap
		elseif c_type == 2 then
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
    	elseif c_type == 3 then
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
			if direction == 0 and n == 0 and nsid == 0xFF then
				local instance = buffer(11,6)
				local pna = string.format("%02x:%02x:%02x:%02x:%02x:%02x",instance(0,1):uint(),instance(1,1):uint(),instance(2,1):uint(),instance(3,1):uint(),instance(4,1):uint(),instance(5,1):uint())
				local upcost = buffer(17,1)
				local dncost = buffer(18,1)
				
				t_prime:add(MAC, buffer(11,6), pna)
				
				info = ", PNA="..pna..", UPCOST="..upcost..", DNCOST="..dncost
			end
			
			pinfo.cols['info'] = "PRO "..tPRO..", N="..n..", RQ="..rq..", TIME="..time..", NSID="..nsid..info
		elseif c_type == 4 then
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
    	elseif c_type == 7 then
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
    	elseif c_type == 9 then
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
	    	pinfo.cols['info'] = PduType[c_type - 1]
	    end
	    
	    t_prime:add(CRC, buffer(frame_len-4,4))
	elseif prime_ht == 1 then
		local instance = buffer(7,6)
		local sna = string.format("%02x:%02x:%02x:%02x:%02x:%02x",instance(0,1):uint(),instance(1,1):uint(),instance(2,1):uint(),instance(3,1):uint(),instance(4,1):uint(),instance(5,1):uint())
		
		t_prime:add(MAC, buffer(7,6), sna)
		t_prime:add(HCS, buffer(13,1))
		
		pinfo.cols['info'] = "PNPDU PNA="..sna
	elseif prime_ht == 2 then
		local qlty = bit.band(buffer(0,1):uint(), 0x07)
		local cnt = bit.band(buffer(2,1):uint(), 0xE0) / 32
		local pos = bit.band(buffer(2,1):uint(), 0x1C) / 4
		local cfp = bit.band(buffer(2,1):uint(), 0x03) * 256 + buffer(3,1):uint()
		local level = bit.band(buffer(4,1):uint(), 0x3F)
		local seq = bit.band(buffer(5,1):uint(), 0xF8) / 8
		local frq = bit.band(buffer(5,1):uint(), 0x07)
		local instance = buffer(6,6)
		local sna = string.format("%02x:%02x:%02x:%02x:%02x:%02x",instance(0,1):uint(),instance(1,1):uint(),instance(2,1):uint(),instance(3,1):uint(),instance(4,1):uint(),instance(5,1):uint())
		
		t_prime:add(QLTY, buffer(0,1), qlty)
		t_prime:add(SID, buffer(1,1))
		t_prime:add(CNT, buffer(2,1), cnt)
		t_prime:add(POS, buffer(2,1), pos)
		t_prime:add(CFP, buffer(2,2), cfp)
		t_prime:add(LEVEL, buffer(4,1), level)
		t_prime:add(SEQ, buffer(5,1), seq)
		t_prime:add(FRQ, buffer(5,1), frq)
		t_prime:add(MAC, buffer(6,6), sna)
		t_prime:add(UPCOST, buffer(12,1))
		t_prime:add(DNCOST, buffer(13,1))
		t_prime:add(CRC, buffer(frame_len-4,4))
		
		pinfo.cols['info'] = "BCN CNT="..cnt..", POS="..pos..", CFP="..cfp..", SEQ="..seq..", FRQ="..frq
	else
		t_prime:add(ControlData, buffer(1,frame_len - 5))
    end
end

-- load the udp port table
udp_table = DissectorTable.get("udp.port")
-- register the protocol to port 7919
udp_table:add(7919, prime_proto)
