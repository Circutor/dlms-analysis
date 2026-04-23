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

-- Generic MAC Header fields
local HDR          = ProtoField.bytes("prime.hdr","Generic MAC Header")
local HDR_UNUSED   = ProtoField.uint8("prime.hdr_unused","Unused",base.HEX)
local HT           = ProtoField.uint8("prime.ht","HT",base.HEX,PrimeHT)
local HDR_RESERVED = ProtoField.uint8("prime.hdr_reserved","Reserved",base.HEX)
local HDR_DO       = ProtoField.uint8("prime.hdr_do","DO",base.HEX,DOType)
local HDR_LEVEL    = ProtoField.uint8("prime.hdr_level","LEVEL",base.HEX)
local HDR_HCS      = ProtoField.uint8("prime.hdr_hcs","HCS",base.HEX)

local ControlData  = ProtoField.bytes("prime.data","Control Data",base.NONE)
local CRC          = ProtoField.uint32("prime.crc","CRC",base.HEX)

-- PKT fields
local PKT          = ProtoField.bytes("prime.pkt","Packet Header")
local PKT_RESERVED = ProtoField.uint8("prime.pkt_reserved","Reserved",base.HEX)
local PKT_NAD      = ProtoField.uint8("prime.pkt_nad","NAD",base.HEX)
local PKT_PRIO     = ProtoField.uint8("prime.pkt_prio","PRIO",base.HEX)
local PKT_C        = ProtoField.uint8("prime.pkt_c","C",base.HEX)
local PKT_LCID     = ProtoField.uint16("prime.pkt_lcid","LCID",base.HEX)
local PKT_CTYPE    = ProtoField.uint16("prime.pkt_ctype","CTYPE",base.HEX)
local PKT_SID      = ProtoField.uint8("prime.pkt_sid","SID",base.HEX)
local PKT_LNID     = ProtoField.uint16("prime.pkt_lnid","LNID",base.HEX)
local PKT_SPAD     = ProtoField.uint8("prime.pkt_spad","SPAD",base.HEX)
local PKT_LEN      = ProtoField.uint16("prime.pkt_len","LEN",base.HEX)
-- PKT fields (v1.4 specific)
local PKT_RM       = ProtoField.uint8("prime.pkt_rm","RM",base.HEX)
local PKT_TREF     = ProtoField.uint8("prime.pkt_tref","TREF",base.HEX)
local PKT_ARQ      = ProtoField.uint8("prime.pkt_arq","ARQ",base.HEX)
local PKT_PSH      = ProtoField.uint8("prime.pkt_psh","PSH",base.HEX)

-- ARQ subheader fields
local ARQ_HDR      = ProtoField.bytes("prime.arq","ARQ Subheader")
local ARQ_M        = ProtoField.uint8("prime.arq_m","M",base.DEC)
local ARQ_FLUSH    = ProtoField.uint8("prime.arq_flush","FLUSH",base.DEC)
local ARQ_PKTID    = ProtoField.uint8("prime.arq_pktid","PKTID",base.DEC)
local ARQ_ACKID    = ProtoField.uint8("prime.arq_ackid","ACKID",base.DEC)
local ARQ_WINSIZE  = ProtoField.uint8("prime.arq_winsize","WINSIZE",base.DEC)
local ARQ_NACKID   = ProtoField.uint8("prime.arq_nackid","NACKID",base.DEC)

local SARType = {
	[0] = "First segment",
	[1] = "Intermediate segment",
	[2] = "Last segment",
	[3] = "Last segment with CRC",
}

-- SAR header fields
local SAR_HDR      = ProtoField.bytes("prime.sar","SAR Header")
local SAR_TYPE     = ProtoField.uint8("prime.sar_type","TYPE",base.DEC,SARType)
local SAR_NSEGS    = ProtoField.uint8("prime.sar_nsegs","NSEGS",base.DEC)
local SAR_SEQ      = ProtoField.uint8("prime.sar_seq","SEQ",base.DEC)
local SAR_CRC      = ProtoField.uint32("prime.sar_crc","SAR CRC",base.HEX)

-- PNH (PNPDU) fields
local PNH          = ProtoField.bytes("prime.pnh","PNPDU Header")
local PNH_RESERVED = ProtoField.uint8("prime.pnh_reserved","Reserved",base.HEX)
local PNH_VER      = ProtoField.uint8("prime.pnh_ver","PNH_VER",base.HEX)
local PNH_CAP_R    = ProtoField.uint8("prime.pnh_cap_r","CAP_R",base.HEX)
local PNH_CAP_BC   = ProtoField.uint8("prime.pnh_cap_bc","CAP_BC",base.HEX)
local MAC          = ProtoField.string("prime.mac","MAC")
local SNA          = ProtoField.string("prime.sna","SNA")
local PNA          = ProtoField.string("prime.pna","PNA")

-- BCN (Beacon PDU) fields
local BCN          = ProtoField.bytes("prime.bcn","Beacon PDU")
local BCN_RESERVED = ProtoField.uint8("prime.bcn_reserved","Reserved",base.HEX)
local BCN_CSMA     = ProtoField.uint8("prime.bcn_csma","CSMA",base.HEX)
local BCN_POS      = ProtoField.uint8("prime.bcn_pos","POS",base.HEX)
local BCN_FRA_LEN  = ProtoField.uint8("prime.bcn_fra_len","FRA_LEN",base.HEX)
local BCN_PHYBC    = ProtoField.uint8("prime.bcn_phybc","PHYBC",base.HEX)
local BCN_MACBC    = ProtoField.uint8("prime.bcn_macbc","MACBC",base.HEX)
local BCN_COST     = ProtoField.uint8("prime.bcn_cost","COST",base.HEX)
local BCN_QLTY     = ProtoField.uint8("prime.bcn_qlty","QLTY",base.HEX)
local BCN_CNT      = ProtoField.uint8("prime.bcn_cnt","CNT",base.HEX)
local BCN_SLT      = ProtoField.uint8("prime.bcn_slt","SLT",base.HEX)
local BCN_CFP      = ProtoField.uint16("prime.bcn_cfp","CFP",base.HEX)
local BCN_UPCOST   = ProtoField.uint8("prime.bcn_upcost","UPCOST",base.HEX)
local BCN_DNCOST   = ProtoField.uint8("prime.bcn_dncost","DNCOST",base.HEX)
local BCN_FRQ      = ProtoField.uint8("prime.bcn_frq","FRQ",base.HEX)
local BCN_SEQ      = ProtoField.uint8("prime.bcn_seq","SEQ",base.HEX)

-- PRO fields
local PRO_HDR     = ProtoField.bytes("prime.pro","PRO Control Data")
local PRO_N       = ProtoField.uint8("prime.pro_n","N",base.HEX)
local PRO_RQ      = ProtoField.uint8("prime.pro_rq","RQ",base.HEX)
local PRO_TIME    = ProtoField.uint8("prime.pro_time","TIME",base.HEX)
local PRO_FRQ     = ProtoField.uint8("prime.pro_frq","FRQ",base.HEX)
local PRO_SEQ     = ProtoField.uint8("prime.pro_seq","SEQ",base.HEX)
local PRO_NSID    = ProtoField.uint8("prime.pro_nsid","NSID",base.HEX)
local PRO_BCN_POS = ProtoField.uint8("prime.pro_bcn_pos","BCN_POS",base.DEC)
local PRO_ACK_F   = ProtoField.uint8("prime.pro_ack","ACK",base.DEC)
local PRO_DS      = ProtoField.uint8("prime.pro_ds","DS",base.DEC)
local PRO_MOD     = ProtoField.uint8("prime.pro_mod","MOD",base.DEC)
local PRO_PN_BC   = ProtoField.uint8("prime.pro_pn_bc","PN_BC",base.DEC)
local PRO_PN_R    = ProtoField.uint8("prime.pro_pn_r","PN_R",base.DEC)
local PRO_SWC_DC  = ProtoField.uint8("prime.pro_swc_dc","SWC_DC",base.DEC)
local PRO_SWC_ARQ = ProtoField.uint8("prime.pro_swc_arq","SWC_ARQ",base.DEC)
local PRO_PNA     = ProtoField.string("prime.pro_pna","PNA")
local PRO_COST    = ProtoField.uint8("prime.pro_cost","COST",base.DEC)
-- PRO fields (v1.3.6 specific)
local PRO_SWC_MC  = ProtoField.uint8("prime.pro_swc_mc","SWC_MC",base.DEC)
local PRO_SWC_PRM = ProtoField.uint8("prime.pro_swc_prm","SWC_PRM",base.DEC)
local PRO_UPCOST  = ProtoField.uint8("prime.pro_upcost","UPCOST",base.DEC)
local PRO_DNCOST  = ProtoField.uint8("prime.pro_dncost","DNCOST",base.DEC)

-- CON fields
local CON_HDR    = ProtoField.bytes("prime.con","CON Control Data")
local CON_N      = ProtoField.uint8("prime.con_n","N",base.DEC)
local CON_D      = ProtoField.uint8("prime.con_d","D",base.DEC)
local CON_ARQ    = ProtoField.uint8("prime.con_arq","ARQ",base.DEC)
local CON_E      = ProtoField.uint8("prime.con_e","E",base.DEC)
local CON_LCID   = ProtoField.uint16("prime.con_lcid","CON.LCID",base.DEC)
local CON_EUI48  = ProtoField.string("prime.con_eui48","EUI-48")
local CON_DCLCID = ProtoField.uint16("prime.con_dclcid","DCLCID",base.DEC)
local CON_DCNAD  = ProtoField.uint8("prime.con_dcnad","DCNAD",base.DEC)
local CON_DCLNID = ProtoField.uint16("prime.con_dclnid","DCLNID",base.HEX)
local CON_DSSID  = ProtoField.uint8("prime.con_dssid","DSSID",base.HEX)
local CON_DCSID  = ProtoField.uint8("prime.con_dcsid","DCSID",base.HEX)
local CON_TYPE   = ProtoField.uint8("prime.con_type","TYPE",base.HEX)
local CON_DLEN   = ProtoField.uint8("prime.con_dlen","DLEN",base.DEC)
local CON_DATA   = ProtoField.bytes("prime.con_data","DATA")

-- REG fields
local REG_HDR     = ProtoField.bytes("prime.reg","REG Control Data")
local REG_N       = ProtoField.uint8("prime.reg_n","N",base.DEC)
local REG_R       = ProtoField.uint8("prime.reg_r","R",base.DEC)
local REG_SPC     = ProtoField.uint8("prime.reg_spc","SPC",base.DEC)
local REG_CAP_SW  = ProtoField.uint8("prime.reg_cap_sw","CAP_SW",base.DEC)
local REG_CAP_PA  = ProtoField.uint8("prime.reg_cap_pa","CAP_PA",base.DEC)
local REG_CAP_CFP = ProtoField.uint8("prime.reg_cap_cfp","CAP_CFP",base.DEC)
local REG_CAP_DC  = ProtoField.uint8("prime.reg_cap_dc","CAP_DC",base.DEC)
local REG_CAP_ARQ = ProtoField.uint8("prime.reg_cap_arq","CAP_ARQ",base.DEC)
local REG_TIME    = ProtoField.uint8("prime.reg_time","TIME",base.DEC)
local REG_EUI48   = ProtoField.string("prime.reg_eui48","EUI-48")
-- REG fields (v1.3.6 specific)
local REG_CAP_MC  = ProtoField.uint8("prime.reg_cap_mc","CAP_MC",base.DEC)
local REG_CAP_PRM = ProtoField.uint8("prime.reg_cap_prm","CAP_PRM",base.DEC)
local REG_SNK     = ProtoField.bytes("prime.reg_snk","SNK")
local REG_AUK     = ProtoField.bytes("prime.reg_auk","AUK")
-- REG fields (v1.4 specific)
local REG_CAP_R   = ProtoField.uint8("prime.reg_cap_r","CAP_R",base.DEC)
local REG_CAP_BC  = ProtoField.uint8("prime.reg_cap_bc","CAP_BC",base.DEC)
local REG_ALV_F   = ProtoField.uint8("prime.reg_alv_f","ALV_F",base.DEC)
local REG_RM_F    = ProtoField.uint8("prime.reg_rm_f","RM_F",base.DEC)
local REG_SAR_SIZE = ProtoField.uint8("prime.reg_sar_size","SAR_SIZE",base.DEC)
local REG_CNT     = ProtoField.bytes("prime.reg_cnt","CNT")
local REG_SWK     = ProtoField.bytes("prime.reg_swk","SWK")
local REG_WK      = ProtoField.bytes("prime.reg_wk","WK")

-- ALV fields (v1.3.6)
local ALV           = ProtoField.bytes("prime.alv","ALV Control Data",base.NONE)
local ALV_RXCNT     = ProtoField.uint8("prime.alv_rxcnt","RXCNT",base.DEC)
local ALV_TXCNT     = ProtoField.uint8("prime.alv_txcnt","TXCNT",base.DEC)
local ALV_SSID      = ProtoField.uint8("prime.alv_ssid","SSID",base.HEX)
local ALV_TIME      = ProtoField.uint8("prime.alv_time","TIME",base.DEC)
-- ALV fields (v1.4)
local ALV_R         = ProtoField.uint8("prime.alv_r","R",base.DEC)
local ALV_RTL       = ProtoField.uint8("prime.alv_rtl","RTL",base.DEC)
local ALV_MIN_LEVEL = ProtoField.uint8("prime.alv_min_level","MIN_LEVEL",base.DEC)
local ALV_TX_SEQ    = ProtoField.uint8("prime.alv_tx_seq","TX_SEQ",base.DEC)
local ALV_RX_ENC    = ProtoField.uint8("prime.alv_rx_enc","RX_ENC",base.HEX)
local ALV_RX_SNR    = ProtoField.uint8("prime.alv_rx_snr","RX_SNR",base.DEC)
local ALV_RX_POW    = ProtoField.uint8("prime.alv_rx_pow","RX_POW",base.DEC)
local ALV_V_LD      = ProtoField.uint8("prime.alv_v_ld","V_LD",base.DEC)
local ALV_REP_D     = ProtoField.uint8("prime.alv_rep_d","REP_D",base.DEC)
local ALV_V_LU      = ProtoField.uint8("prime.alv_v_lu","V_LU",base.DEC)
local ALV_REP_U     = ProtoField.uint8("prime.alv_rep_u","REP_U",base.DEC)

-- BSI fields
local BSI_HDR = ProtoField.bytes("prime.bsi","BSI Control Data")
local BSI_FRQ = ProtoField.uint8("prime.bsi_frq","FRQ",base.DEC)
local BSI_SLT = ProtoField.uint8("prime.bsi_slt","SLT",base.DEC)
local BSI_SEQ = ProtoField.uint8("prime.bsi_seq","SEQ",base.DEC)

-- PRM fields
local PRM_HDR = ProtoField.bytes("prime.prm","PRM Control Data")
local PRM_R   = ProtoField.uint8("prime.prm_r","R",base.DEC)
local PRM_N   = ProtoField.uint8("prime.prm_n","N",base.DEC)
local PRM_SNR = ProtoField.uint8("prime.prm_snr","SNR",base.DEC)

prime_proto.fields = {
	-- Generic MAC Header
	HDR, HDR_UNUSED, HT, HDR_RESERVED, HDR_DO, HDR_LEVEL, HDR_HCS,
	ControlData, CRC,
	-- PKT
	PKT, PKT_RESERVED, PKT_NAD, PKT_PRIO, PKT_C, PKT_LCID, PKT_CTYPE, PKT_SID, PKT_LNID, PKT_SPAD, PKT_LEN,
	PKT_RM, PKT_TREF, PKT_ARQ, PKT_PSH,
	-- ARQ subheader
	ARQ_HDR, ARQ_M, ARQ_FLUSH, ARQ_PKTID, ARQ_ACKID, ARQ_WINSIZE, ARQ_NACKID,
	-- SAR header
	SAR_HDR, SAR_TYPE, SAR_NSEGS, SAR_SEQ, SAR_CRC,
	-- PNH
	PNH, PNH_RESERVED, PNH_VER, PNH_CAP_R, PNH_CAP_BC, MAC, SNA, PNA,
	-- BCN
	BCN, BCN_RESERVED, BCN_CSMA, BCN_POS, BCN_FRA_LEN, BCN_PHYBC, BCN_MACBC, BCN_COST,
	BCN_QLTY, BCN_CNT, BCN_SLT, BCN_CFP, BCN_UPCOST, BCN_DNCOST, BCN_FRQ, BCN_SEQ,
	-- PRO
	PRO_HDR, PRO_N, PRO_RQ, PRO_TIME, PRO_NSID, PRO_BCN_POS, PRO_ACK_F, PRO_DS, PRO_MOD,
	PRO_PN_BC, PRO_PN_R, PRO_SWC_DC, PRO_SWC_ARQ, PRO_PNA, PRO_COST,
	PRO_SWC_MC, PRO_SWC_PRM, PRO_UPCOST, PRO_DNCOST, PRO_FRQ, PRO_SEQ,
	-- CON
	CON_HDR, CON_N, CON_D, CON_ARQ, CON_E, CON_LCID, CON_EUI48,
	CON_DCLCID, CON_DCNAD, CON_DCLNID, CON_DSSID, CON_DCSID, CON_TYPE, CON_DLEN, CON_DATA,
	-- REG
	REG_HDR, REG_N, REG_R, REG_SPC, REG_CAP_SW, REG_CAP_PA, REG_CAP_CFP, REG_CAP_DC, REG_CAP_ARQ, REG_TIME, REG_EUI48,
	REG_CAP_MC, REG_CAP_PRM, REG_SNK, REG_AUK,
	REG_CAP_R, REG_CAP_BC, REG_ALV_F, REG_RM_F, REG_SAR_SIZE, REG_CNT, REG_SWK, REG_WK,
	-- ALV
	ALV, ALV_RXCNT, ALV_TXCNT, ALV_SSID, ALV_TIME,
	ALV_R, ALV_RTL, ALV_MIN_LEVEL, ALV_TX_SEQ, ALV_RX_ENC, ALV_RX_SNR, ALV_RX_POW,
	ALV_V_LD, ALV_REP_D, ALV_V_LU, ALV_REP_U,
	-- BSI
	BSI_HDR, BSI_FRQ, BSI_SLT, BSI_SEQ,
	-- PRM
	PRM_HDR, PRM_R, PRM_N, PRM_SNR}

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

local function dissect_pnpdu(buffer, pinfo, t_prime)
	local frame_len = buffer:len()
	if frame_len < 14 then
		pinfo.cols['info'] = "PNPDU (truncated)"
		return
	end

	local ver = extract_bits(buffer(0,1), 0, 2)
	local prime_ht = extract_bits(buffer(0,1), 2, 2)
	local sna_range = buffer(1,6)
	local pna_range = buffer(7,6)
	local sna = format_mac(sna_range)
	local pna = format_mac(pna_range)

	local t_pnh = t_prime:add(PNH, buffer(0,14))
	t_pnh:add(HT, buffer(0,1), prime_ht)
	if ver == 0 then
		local pnh_reserved = extract_bits(buffer(0,1), 4, 4)
		t_pnh:add(PNH_RESERVED, buffer(0,1), pnh_reserved)
	else
		local pnh_ver = extract_bits(buffer(0,1), 4, 2)
		local cap_r = extract_bits(buffer(0,1), 6, 1)
		local cap_bc = extract_bits(buffer(0,1), 7, 1)
		t_pnh:add(PNH_VER, buffer(0,1), pnh_ver)
		t_pnh:add(PNH_CAP_R, buffer(0,1), cap_r)
		t_pnh:add(PNH_CAP_BC, buffer(0,1), cap_bc)
	end
	t_pnh:add(SNA, sna_range, sna)
	t_pnh:add(PNA, pna_range, pna)
	t_pnh:add(HDR_HCS, buffer(13,1))

	if ver == 0 then
		pinfo.cols['info'] = "PNPDU SNA="..sna..", PNA="..pna
	else
		local pnh_ver = extract_bits(buffer(0,1), 4, 2)
		local cap_r = extract_bits(buffer(0,1), 6, 1)
		local cap_bc = extract_bits(buffer(0,1), 7, 1)
		pinfo.cols['info'] = "PNPDU VER="..pnh_ver..", CAP_R="..cap_r..", CAP_BC="..cap_bc..", SNA="..sna..", PNA="..pna
	end
end

local function dissect_bcn(buffer, pinfo, t_prime)
	local frame_len = buffer:len()
	if frame_len < 18 then
		pinfo.cols['info'] = "BCN (truncated)"
		return
	end

	local ver = extract_bits(buffer(0,1), 0, 2)
	local prime_ht = extract_bits(buffer(0,1), 2, 2)

	if ver == 0 then
		-- PRIME v1.3.6 BCN
		-- Byte 0: Unused(2), HT(2), Reserved(1), QLTY(3)
		-- Byte 1: SID(8)
		-- Bytes 2-3: CNT(3), SLT(3), CFP(10)
		-- Byte 4: Reserved(1), LEVEL(6), <lsb in next byte>
		-- Byte 5: SEQ(5), FRQ(3)
		-- Bytes 6-11: SNA(48)
		-- Byte 12: UPCOST(8)
		-- Byte 13: DNCOST(8)
		-- Bytes 14-17: CRC(32)
		local bcn_reserved_hdr = extract_bits(buffer(0,1), 4, 1)
		local qlty = extract_bits(buffer(0,1), 5, 3)
		local cnt = extract_bits(buffer(2,1), 0, 3)
		local slt = extract_bits(buffer(2,1), 3, 3)
		local cfp = extract_bits(buffer(2,2), 6, 10)
		local bcn_reserved_lvl = extract_bits(buffer(4,1), 0, 1)
		local level = extract_bits(buffer(4,1), 1, 6)
		local seq = extract_bits(buffer(5,1), 0, 5)
		local frq = extract_bits(buffer(5,1), 5, 3)
		local sna = format_mac(buffer(6,6))

		local t_bcn = t_prime:add(BCN, buffer(0,18))
		t_bcn:add(HT, buffer(0,1), prime_ht)
		t_bcn:add(BCN_RESERVED, buffer(0,1), bcn_reserved_hdr)
		t_bcn:add(BCN_QLTY, buffer(0,1), qlty)
		t_bcn:add(PKT_SID, buffer(1,1))
		t_bcn:add(BCN_CNT, buffer(2,1), cnt)
		t_bcn:add(BCN_SLT, buffer(2,1), slt)
		t_bcn:add(BCN_CFP, buffer(2,2), cfp)
		t_bcn:add(BCN_RESERVED, buffer(4,1), bcn_reserved_lvl)
		t_bcn:add(HDR_LEVEL, buffer(4,1), level)
		t_bcn:add(BCN_SEQ, buffer(5,1), seq)
		t_bcn:add(BCN_FRQ, buffer(5,1), frq)
		t_bcn:add(SNA, buffer(6,6), sna)
		t_bcn:add(BCN_UPCOST, buffer(12,1))
		t_bcn:add(BCN_DNCOST, buffer(13,1))
		t_bcn:add(CRC, buffer(14,4))

		pinfo.cols['info'] = "BCN CNT="..cnt..", SLT="..slt..", CFP="..cfp..", SEQ="..seq..", FRQ="..frq
	else
		-- PRIME v1.4 BCN
		-- Byte 0: Unused(2), HT(2), QLTY(4)
		-- Byte 1: SID(8)
		-- Bytes 2-3: LEVEL(6), CFP(10)
		-- Byte 4: CSMA(1), POS(7)
		-- Byte 5: FRA_LEN(2), PHYBC(1), MACBC(1), Reserved(4)
		-- Byte 6: SEQ(5), FRQ(3)
		-- Bytes 7-12: SNA(48)
		-- Byte 13: COST(8)
		-- Bytes 14-17: CRC(32)
		local qlty = extract_bits(buffer(0,1), 4, 4)
		local level = extract_bits(buffer(2,1), 0, 6)
		local cfp = extract_bits(buffer(2,2), 6, 10)
		local csma = extract_bits(buffer(4,1), 0, 1)
		local pos = extract_bits(buffer(4,1), 1, 7)
		local fra_len = extract_bits(buffer(5,1), 0, 2)
		local phybc = extract_bits(buffer(5,1), 2, 1)
		local macbc = extract_bits(buffer(5,1), 3, 1)
		local seq = extract_bits(buffer(6,1), 0, 5)
		local frq = extract_bits(buffer(6,1), 5, 3)
		local sna = format_mac(buffer(7,6))

		local t_bcn = t_prime:add(BCN, buffer(0,18))
		t_bcn:add(HT, buffer(0,1), prime_ht)
		t_bcn:add(BCN_QLTY, buffer(0,1), qlty)
		t_bcn:add(PKT_SID, buffer(1,1))
		t_bcn:add(HDR_LEVEL, buffer(2,1), level)
		t_bcn:add(BCN_CFP, buffer(2,2), cfp)
		t_bcn:add(BCN_CSMA, buffer(4,1), csma)
		t_bcn:add(BCN_POS, buffer(4,1), pos)
		t_bcn:add(BCN_FRA_LEN, buffer(5,1), fra_len)
		t_bcn:add(BCN_PHYBC, buffer(5,1), phybc)
		t_bcn:add(BCN_MACBC, buffer(5,1), macbc)
		t_bcn:add(BCN_SEQ, buffer(6,1), seq)
		t_bcn:add(BCN_FRQ, buffer(6,1), frq)
		t_bcn:add(SNA, buffer(7,6), sna)
		t_bcn:add(BCN_COST, buffer(13,1))
		t_bcn:add(CRC, buffer(14,4))

		pinfo.cols['info'] = "BCN CFP="..cfp..", SEQ="..seq..", FRQ="..frq
	end
end

local function dissect_reg(buffer, pinfo, t_prime, payload_offset, payload_len, ver, direction, lnid)
	-- Both versions: minimum 8 bytes (2 capability bytes + 6 EUI-48)
	if payload_len < 8 then
		pinfo.cols['info'] = "REG (truncated)"
		if payload_len > 0 then
			t_prime:add(ControlData, buffer(payload_offset, payload_len))
		end
		return
	end

	-- Byte 0 fields common to both versions
	local n   = extract_bits(buffer(payload_offset, 1), 0, 1)
	local r   = extract_bits(buffer(payload_offset, 1), 1, 1)
	local spc = extract_bits(buffer(payload_offset, 1), 2, 2)

	-- Byte 1 fields common to both versions
	local cap_cfp = extract_bits(buffer(payload_offset+1, 1), 0, 1)
	local cap_dc  = extract_bits(buffer(payload_offset+1, 1), 1, 1)
	local cap_arq = extract_bits(buffer(payload_offset+1, 1), 4, 1)
	local time    = extract_bits(buffer(payload_offset+1, 1), 5, 3)

	-- EUI-48 (bytes 2-7)
	local eui48 = format_mac(buffer(payload_offset+2, 6))

	local t_reg = t_prime:add(REG_HDR, buffer(payload_offset, payload_len))
	t_reg:add(REG_N,   buffer(payload_offset, 1), n)
	t_reg:add(REG_R,   buffer(payload_offset, 1), r)
	t_reg:add(REG_SPC, buffer(payload_offset, 1), spc)

	if ver == 0 then
		-- v1.3.6 Byte 0: N(1),R(1),SPC(2),Reserved(2),CAP_SW(1),CAP_PA(1)
		-- v1.3.6 Byte 1: CAP_CFP(1),CAP_DC(1),CAP_MC(1),CAP_PRM(1),CAP_ARQ(1),TIME(3)
		local cap_sw  = extract_bits(buffer(payload_offset, 1), 6, 1)
		local cap_pa  = extract_bits(buffer(payload_offset, 1), 7, 1)
		local cap_mc  = extract_bits(buffer(payload_offset+1, 1), 2, 1)
		local cap_prm = extract_bits(buffer(payload_offset+1, 1), 3, 1)
		t_reg:add(REG_CAP_SW,  buffer(payload_offset, 1), cap_sw)
		t_reg:add(REG_CAP_PA,  buffer(payload_offset, 1), cap_pa)
		t_reg:add(REG_CAP_CFP, buffer(payload_offset+1, 1), cap_cfp)
		t_reg:add(REG_CAP_DC,  buffer(payload_offset+1, 1), cap_dc)
		t_reg:add(REG_CAP_MC,  buffer(payload_offset+1, 1), cap_mc)
		t_reg:add(REG_CAP_PRM, buffer(payload_offset+1, 1), cap_prm)
		t_reg:add(REG_CAP_ARQ, buffer(payload_offset+1, 1), cap_arq)
		t_reg:add(REG_TIME,    buffer(payload_offset+1, 1), time)
		t_reg:add(REG_EUI48,   buffer(payload_offset+2, 6), eui48)
		-- Optional security fields (SPC >= 1): SNK(16) + AUK(16)
		if spc >= 1 and payload_len >= 8 + 16 then
			t_reg:add(REG_SNK, buffer(payload_offset+8, 16))
			if payload_len >= 8 + 32 then
				t_reg:add(REG_AUK, buffer(payload_offset+24, 16))
			end
		end
	else
		-- v1.4 Byte 0: N(1),R(1),SPC(2),CAP_R(1),CAP_BC(1),CAP_SW(1),CAP_PA(1)
		-- v1.4 Byte 1: CAP_CFP(1),CAP_DC(1),ALV_F(1),Reserved(1),CAP_ARQ(1),TIME(3)
		local cap_r  = extract_bits(buffer(payload_offset, 1), 4, 1)
		local cap_bc = extract_bits(buffer(payload_offset, 1), 5, 1)
		local cap_sw = extract_bits(buffer(payload_offset, 1), 6, 1)
		local cap_pa = extract_bits(buffer(payload_offset, 1), 7, 1)
		local alv_f  = extract_bits(buffer(payload_offset+1, 1), 2, 1)
		t_reg:add(REG_CAP_R,   buffer(payload_offset, 1), cap_r)
		t_reg:add(REG_CAP_BC,  buffer(payload_offset, 1), cap_bc)
		t_reg:add(REG_CAP_SW,  buffer(payload_offset, 1), cap_sw)
		t_reg:add(REG_CAP_PA,  buffer(payload_offset, 1), cap_pa)
		t_reg:add(REG_CAP_CFP, buffer(payload_offset+1, 1), cap_cfp)
		t_reg:add(REG_CAP_DC,  buffer(payload_offset+1, 1), cap_dc)
		t_reg:add(REG_ALV_F,   buffer(payload_offset+1, 1), alv_f)
		t_reg:add(REG_CAP_ARQ, buffer(payload_offset+1, 1), cap_arq)
		t_reg:add(REG_TIME,    buffer(payload_offset+1, 1), time)
		t_reg:add(REG_EUI48,   buffer(payload_offset+2, 6), eui48)
		-- Optional security fields (SPC >= 1):
		-- Byte 8: RM_F(2), SAR_SIZE(3), Reserved(3)
		-- Bytes 9-12: CNT (4 bytes)
		-- Bytes 13-36: SWK (24 bytes)
		-- Bytes 37-60: WK (24 bytes)
		if spc >= 1 and payload_len >= 13 then
			local rm_f     = extract_bits(buffer(payload_offset+8, 1), 0, 2)
			local sar_size = extract_bits(buffer(payload_offset+8, 1), 2, 3)
			t_reg:add(REG_RM_F,     buffer(payload_offset+8, 1), rm_f)
			t_reg:add(REG_SAR_SIZE, buffer(payload_offset+8, 1), sar_size)
			t_reg:add(REG_CNT,      buffer(payload_offset+9, 4))
			if payload_len >= 8 + 5 + 24 then
				t_reg:add(REG_SWK, buffer(payload_offset+13, 24))
				if payload_len >= 8 + 5 + 48 then
					t_reg:add(REG_WK, buffer(payload_offset+37, 24))
				end
			end
		end
	end

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

	pinfo.cols['info'] = "REG " .. (tREG or "UNK") .. " LNID=" .. string.format("0x%04x", lnid) .. " EUI48=" .. eui48 .. " TIME=" .. time .. " SPC=" .. spc
end

local function dissect_con(buffer, pinfo, t_prime, payload_offset, payload_len, direction, lnid)
	-- Minimum: 2 bytes header (flags+LCID) + 1 TYPE + 1 DLEN
	if payload_len < 4 then
		pinfo.cols['info'] = "CON (truncated)"
		if payload_len > 0 then
			t_prime:add(ControlData, buffer(payload_offset, payload_len))
		end
		return
	end

	-- Byte 0: N(1), D(1), ARQ(1), E(1), Reserved(3), LCID[8]
	-- Byte 1: LCID[7..0]
	local n   = extract_bits(buffer(payload_offset, 1), 0, 1)
	local d   = extract_bits(buffer(payload_offset, 1), 1, 1)
	local arq = extract_bits(buffer(payload_offset, 1), 2, 1)
	local e   = extract_bits(buffer(payload_offset, 1), 3, 1)
	local con_lcid = extract_bits(buffer(payload_offset, 2), 7, 9)

	local tCON
	if direction == 0 and n == 0 then
		tCON = "REQ_S"
	elseif direction == 1 and n == 0 then
		tCON = "REQ_B"
	elseif direction == 0 and n == 1 then
		tCON = "CLS_S"
	elseif direction == 1 and n == 1 then
		tCON = "CLS_B"
	end

	local t_con = t_prime:add(CON_HDR, buffer(payload_offset, payload_len))
	t_con:add(CON_N,   buffer(payload_offset, 1), n)
	t_con:add(CON_D,   buffer(payload_offset, 1), d)
	t_con:add(CON_ARQ, buffer(payload_offset, 1), arq)
	t_con:add(CON_E,   buffer(payload_offset, 1), e)
	t_con:add(CON_LCID, buffer(payload_offset, 2), con_lcid)

	local dyn_offset = payload_offset + 2

	-- Optional EUI-48 (present if E=1)
	if e == 1 then
		if payload_offset + payload_len >= dyn_offset + 6 then
			local eui48 = format_mac(buffer(dyn_offset, 6))
			t_con:add(CON_EUI48, buffer(dyn_offset, 6), eui48)
			dyn_offset = dyn_offset + 6
		end
	end

	-- Optional direct connection fields (present if D=1)
	-- Reserved(7), DCLCID(9)  → 2 bytes
	-- DCNAD(1), Reserved(1), DCLNID(14) → 2 bytes
	-- DSSID(8), DCSID(8) → 2 bytes
	if d == 1 then
		if payload_offset + payload_len >= dyn_offset + 6 then
			local dclcid = extract_bits(buffer(dyn_offset, 2), 7, 9)
			local dcnad  = extract_bits(buffer(dyn_offset+2, 1), 0, 1)
			local dclnid = extract_bits(buffer(dyn_offset+2, 2), 2, 14)
			local dssid  = buffer(dyn_offset+4, 1):uint()
			local dcsid  = buffer(dyn_offset+5, 1):uint()
			t_con:add(CON_DCLCID, buffer(dyn_offset,   2), dclcid)
			t_con:add(CON_DCNAD,  buffer(dyn_offset+2, 1), dcnad)
			t_con:add(CON_DCLNID, buffer(dyn_offset+2, 2), dclnid)
			t_con:add(CON_DSSID,  buffer(dyn_offset+4, 1), dssid)
			t_con:add(CON_DCSID,  buffer(dyn_offset+5, 1), dcsid)
			dyn_offset = dyn_offset + 6
		end
	end

	-- TYPE and DLEN (always present)
	if payload_offset + payload_len >= dyn_offset + 2 then
		local con_type = buffer(dyn_offset, 1):uint()
		local con_dlen = buffer(dyn_offset+1, 1):uint()
		t_con:add(CON_TYPE, buffer(dyn_offset,   1))
		t_con:add(CON_DLEN, buffer(dyn_offset+1, 1))
		dyn_offset = dyn_offset + 2
		if con_dlen > 0 and payload_offset + payload_len >= dyn_offset + con_dlen then
			t_con:add(CON_DATA, buffer(dyn_offset, con_dlen))
		end
	end

	pinfo.cols['info'] = "CON " .. (tCON or "UNK") .. " LNID=" .. string.format("0x%04x", lnid) .. " LCID=" .. con_lcid
end

local function dissect_pro(buffer, pinfo, t_prime, payload_offset, payload_len, ver, direction, lnid)
	if payload_len < 2 then
		pinfo.cols['info'] = "PRO (truncated)"
		if payload_len > 0 then
			t_prime:add(ControlData, buffer(payload_offset, payload_len))
		end
		return
	end

	local t_pro = t_prime:add(PRO_HDR, buffer(payload_offset, payload_len))

	local n    = extract_bits(buffer(payload_offset, 1), 0, 1)
	local nsid = buffer(payload_offset+1, 1):uint()

	if ver == 0 then
		-- v1.3.6: Byte0: N(1),Reserved(1),RQ(3),TIME(3) · Byte1: NSID(8)
		local rq   = extract_bits(buffer(payload_offset, 1), 2, 3)
		local time = extract_bits(buffer(payload_offset, 1), 5, 3)
		t_pro:add(PRO_N,    buffer(payload_offset,   1), n)
		t_pro:add(PRO_RQ,   buffer(payload_offset,   1), rq)
		t_pro:add(PRO_TIME, buffer(payload_offset,   1), time)
		t_pro:add(PRO_NSID, buffer(payload_offset+1, 1))

		local tPRO
		if direction == 0 and n == 0 and nsid == 0xFF then
			tPRO = "REQ_S"
		elseif direction == 1 and n == 0 and nsid ~= 0xFF then
			tPRO = "REQ_B"
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
		-- PRO_REQ_S includes PNA(6B)+UPCOST(1B)+DNCOST(1B)+SWC caps(1B)
		if direction == 0 and n == 0 and nsid == 0xFF and payload_len >= 10 then
			local pna    = format_mac(buffer(payload_offset+2, 6))
			local upcost = buffer(payload_offset+8, 1):uint()
			local dncost = buffer(payload_offset+9, 1):uint()
			t_pro:add(PRO_PNA,    buffer(payload_offset+2, 6), pna)
			t_pro:add(PRO_UPCOST, buffer(payload_offset+8, 1), upcost)
			t_pro:add(PRO_DNCOST, buffer(payload_offset+9, 1), dncost)
			info = " PNA=" .. pna .. " UPCOST=" .. upcost .. " DNCOST=" .. dncost
			if payload_len >= 11 then
				local swc_dc  = extract_bits(buffer(payload_offset+10, 1), 3, 1)
				local swc_mc  = extract_bits(buffer(payload_offset+10, 1), 4, 1)
				local swc_prm = extract_bits(buffer(payload_offset+10, 1), 5, 1)
				local swc_arq = extract_bits(buffer(payload_offset+10, 1), 6, 1)
				t_pro:add(PRO_SWC_DC,  buffer(payload_offset+10, 1), swc_dc)
				t_pro:add(PRO_SWC_MC,  buffer(payload_offset+10, 1), swc_mc)
				t_pro:add(PRO_SWC_PRM, buffer(payload_offset+10, 1), swc_prm)
				t_pro:add(PRO_SWC_ARQ, buffer(payload_offset+10, 1), swc_arq)
			end
		end

		pinfo.cols['info'] = "PRO " .. (tPRO or "UNK") .. " LNID=" .. string.format("0x%04x", lnid) .. " N=" .. n .. " RQ=" .. rq .. " TIME=" .. time .. " NSID=" .. string.format("0x%02x", nsid) .. info
	else
		-- v1.4: Byte0: N(1),BCN_POS(7) · Byte1: NSID(8)
		--        Byte2: RQ(3),TIME(3),SEQ[4..3](2) · Byte3: SEQ[2..0](3),FRQ(3),MOD(2)
		--        Byte4: ACK(1),DS(1),Reserved(6)
		if payload_len < 5 then
			pinfo.cols['info'] = "PRO (truncated)"
			return
		end
		local bcn_pos = extract_bits(buffer(payload_offset,   1), 1, 7)
		local rq      = extract_bits(buffer(payload_offset+2, 1), 0, 3)
		local time    = extract_bits(buffer(payload_offset+2, 1), 3, 3)
		local seq     = extract_bits(buffer(payload_offset+2, 2), 6, 5)
		local frq     = extract_bits(buffer(payload_offset+3, 1), 3, 3)
		local mod     = extract_bits(buffer(payload_offset+3, 1), 6, 2)
		local ack     = extract_bits(buffer(payload_offset+4, 1), 0, 1)
		local ds      = extract_bits(buffer(payload_offset+4, 1), 1, 1)

		t_pro:add(PRO_N,       buffer(payload_offset,   1), n)
		t_pro:add(PRO_BCN_POS, buffer(payload_offset,   1), bcn_pos)
		t_pro:add(PRO_NSID,    buffer(payload_offset+1, 1))
		t_pro:add(PRO_RQ,      buffer(payload_offset+2, 1), rq)
		t_pro:add(PRO_TIME,    buffer(payload_offset+2, 1), time)
		t_pro:add(PRO_SEQ,     buffer(payload_offset+2, 2), seq)
		t_pro:add(PRO_FRQ,     buffer(payload_offset+3, 1), frq)
		t_pro:add(PRO_MOD,     buffer(payload_offset+3, 1), mod)
		t_pro:add(PRO_ACK_F,   buffer(payload_offset+4, 1), ack)
		t_pro:add(PRO_DS,      buffer(payload_offset+4, 1), ds)

		local tPRO
		if direction == 0 and n == 0 and ack == 0 then
			tPRO = "REQ_S"
		elseif direction == 1 and n == 0 and ack == 0 and nsid ~= 0xFF then
			tPRO = "REQ_B"
		elseif n == 0 and ack == 1 and nsid ~= 0xFF then
			tPRO = "ACK"
		elseif n == 1 and ack == 1 and nsid ~= 0xFF then
			tPRO = "NACK"
		elseif direction == 0 and n == 1 and ack == 0 and nsid ~= 0xFF then
			tPRO = "DEM_S"
		elseif direction == 1 and n == 1 and ack == 0 and nsid ~= 0xFF then
			tPRO = "DEM_B"
		end

		local info = ""
		-- PRO_REQ_S includes: caps byte + PNA(6B) + COST(1B)
		if direction == 0 and n == 0 and ack == 0 and payload_len >= 13 then
			local pn_bc   = extract_bits(buffer(payload_offset+5, 1), 0, 1)
			local pn_r    = extract_bits(buffer(payload_offset+5, 1), 1, 1)
			local swc_dc  = extract_bits(buffer(payload_offset+5, 1), 2, 1)
			local swc_arq = extract_bits(buffer(payload_offset+5, 1), 3, 1)
			local pna     = format_mac(buffer(payload_offset+6, 6))
			local cost    = buffer(payload_offset+12, 1):uint()
			t_pro:add(PRO_PN_BC,   buffer(payload_offset+5, 1), pn_bc)
			t_pro:add(PRO_PN_R,    buffer(payload_offset+5, 1), pn_r)
			t_pro:add(PRO_SWC_DC,  buffer(payload_offset+5, 1), swc_dc)
			t_pro:add(PRO_SWC_ARQ, buffer(payload_offset+5, 1), swc_arq)
			t_pro:add(PRO_PNA,     buffer(payload_offset+6, 6), pna)
			t_pro:add(PRO_COST,    buffer(payload_offset+12, 1), cost)
			info = " PNA=" .. pna .. " COST=" .. cost
		end

		pinfo.cols['info'] = "PRO " .. (tPRO or "UNK") .. " LNID=" .. string.format("0x%04x", lnid) .. " N=" .. n .. " RQ=" .. rq .. " TIME=" .. time .. " NSID=" .. string.format("0x%02x", nsid) .. info
	end
end

local function dissect_bsi(buffer, pinfo, t_prime, payload_offset, payload_len, direction, lnid)
	-- BSI: Byte 0: Reserved(5), FRQ(3)  ·  Byte 1: SLT(3), SEQ(5)
	if payload_len < 2 then
		pinfo.cols['info'] = "BSI (truncated)"
		if payload_len > 0 then
			t_prime:add(ControlData, buffer(payload_offset, payload_len))
		end
		return
	end
	local frq = extract_bits(buffer(payload_offset,   1), 5, 3)
	local slt = extract_bits(buffer(payload_offset+1, 1), 0, 3)
	local seq = extract_bits(buffer(payload_offset+1, 1), 3, 5)
	local t_bsi = t_prime:add(BSI_HDR, buffer(payload_offset, 2))
	t_bsi:add(BSI_FRQ, buffer(payload_offset,   1), frq)
	t_bsi:add(BSI_SLT, buffer(payload_offset+1, 1), slt)
	t_bsi:add(BSI_SEQ, buffer(payload_offset+1, 1), seq)
	local tBSI = (direction == 0) and "ACK" or "IND"
	pinfo.cols['info'] = "BSI " .. tBSI .. " LNID=" .. string.format("0x%04x", lnid) .. " FRQ=" .. frq .. " SLT=" .. slt .. " SEQ=" .. seq
end

local function dissect_alv(buffer, pinfo, t_prime, payload_offset, payload_len, ver, direction, lnid)
	if ver == 0 then
		-- PRIME v1.3.6 ALV
		-- Byte 0: RXCNT(3), TXCNT(3), Reserved(2)
		-- Byte 1: Reserved(5), TIME(3)
		-- Byte 2: SSID(8)
		if payload_len < 3 then
			pinfo.cols['info'] = "ALV (truncated)"
			return
		end

		local alv_frame = buffer(payload_offset, 3)
		local rxcnt = extract_bits(alv_frame, 0, 3)
		local txcnt = extract_bits(alv_frame, 3, 3)
		local time  = extract_bits(alv_frame, 13, 3)
		local ssid  = extract_bits(alv_frame, 16, 8)

		local t_alv = t_prime:add(ALV, buffer(payload_offset, 3))
		t_alv:add(ALV_RXCNT, buffer(payload_offset, 1), rxcnt)
		t_alv:add(ALV_TXCNT, buffer(payload_offset, 1), txcnt)
		t_alv:add(ALV_TIME,  buffer(payload_offset+1, 1), time)
		t_alv:add(ALV_SSID,  buffer(payload_offset+2, 1), ssid)
		local tALV = (direction == 0) and "ALV_S" or "ALV_B"
		pinfo.cols['info'] = tALV .. " LNID=" .. lnid .. " RXCNT=" .. rxcnt .. " TXCNT=" .. txcnt .. " TIME=" .. time .. " SSID=" .. string.format("0x%02x", ssid)
	else
		-- PRIME v1.4 ALV
		-- ALV.R distinguishes request/response (R=1) from acknowledge (R=0)
		if payload_len < 1 then
			pinfo.cols['info'] = "ALV (truncated)"
			return
		end

		local alv_r = extract_bits(buffer(payload_offset, 1), 0, 1)
		if alv_r == 0 then
			-- ALV_ACK_B (DO=1) or ALV_ACK_S (DO=0)
			-- Byte 0: R(1), Reserved(3), RX_ENC(4)
			-- Byte 1: RX_SNR(4), RX_POW(4)
			if payload_len < 2 then
				pinfo.cols['info'] = "ALV ACK (truncated)"
				return
			end

			local alv_frame = buffer(payload_offset, 2)
			local rx_enc = extract_bits(alv_frame, 4, 4)
			local rx_snr = extract_bits(alv_frame, 8, 4)
			local rx_pow = extract_bits(alv_frame, 12, 4)

			local t_alv = t_prime:add(ALV, buffer(payload_offset, 2))
			t_alv:add(ALV_R,      buffer(payload_offset, 1), alv_r)
			t_alv:add(ALV_RX_ENC, buffer(payload_offset, 1), rx_enc)
			t_alv:add(ALV_RX_SNR, buffer(payload_offset+1, 1), rx_snr)
			t_alv:add(ALV_RX_POW, buffer(payload_offset+1, 1), rx_pow)
			local tALV = (direction == 0) and "ALV_ACK_S" or "ALV_ACK_B"
			pinfo.cols['info'] = tALV .. " LNID=" .. lnid .. " RX_ENC=" .. rx_enc .. " RX_SNR=" .. rx_snr .. " RX_POW=" .. rx_pow
		else
			-- ALV_REQ_B (DO=1) or ALV_RSP_S/ALV_RSP_ACK (DO=0)
			-- Byte 0: R(1), RTL(4), TIME(3)
			-- Byte 1: MIN_LEVEL(6), Reserved(2)
			-- Byte 2: TX_SEQ(3), Reserved(5)
			-- Bytes 3+: per-hop records, each 1 byte:
			--   V_LD(1), REP_D(3), V_LU(1), REP_U(3)
			if payload_len < 3 then
				pinfo.cols['info'] = "ALV REQ/RSP (truncated)"
				return
			end

			local rtl       = extract_bits(buffer(payload_offset, 1), 1, 4)
			local time      = extract_bits(buffer(payload_offset, 1), 5, 3)
			local min_level = extract_bits(buffer(payload_offset+1, 1), 0, 6)
			local tx_seq    = extract_bits(buffer(payload_offset+2, 1), 0, 3)
			local t_alv = t_prime:add(ALV, buffer(payload_offset, payload_len))
			t_alv:add(ALV_R,         buffer(payload_offset, 1), alv_r)
			t_alv:add(ALV_RTL,       buffer(payload_offset, 1), rtl)
			t_alv:add(ALV_TIME,      buffer(payload_offset, 1), time)
			t_alv:add(ALV_MIN_LEVEL, buffer(payload_offset+1, 1), min_level)
			t_alv:add(ALV_TX_SEQ,    buffer(payload_offset+2, 1), tx_seq)
			-- Per-hop records starting at byte 3
			local hop = 0
			local rec_offset = payload_offset + 3
			while rec_offset < payload_offset + payload_len do
				local v_ld  = extract_bits(buffer(rec_offset, 1), 0, 1)
				local rep_d = extract_bits(buffer(rec_offset, 1), 1, 3)
				local v_lu  = extract_bits(buffer(rec_offset, 1), 4, 1)
				local rep_u = extract_bits(buffer(rec_offset, 1), 5, 3)
				local t_hop = t_alv:add(buffer(rec_offset, 1), "Hop " .. hop .. ": V_LD=" .. v_ld .. " REP_D=" .. rep_d .. " V_LU=" .. v_lu .. " REP_U=" .. rep_u)
				t_hop:add(ALV_V_LD,  buffer(rec_offset, 1), v_ld)
				t_hop:add(ALV_REP_D, buffer(rec_offset, 1), rep_d)
				t_hop:add(ALV_V_LU,  buffer(rec_offset, 1), v_lu)
				t_hop:add(ALV_REP_U, buffer(rec_offset, 1), rep_u)
				hop = hop + 1
				rec_offset = rec_offset + 1
			end
			local tALV = (direction == 0) and "ALV_RSP_S" or "ALV_REQ_B"
			pinfo.cols['info'] = tALV .. " LNID=" .. lnid .. " RTL=" .. rtl .. " TIME=" .. time .. " TX_SEQ=" .. tx_seq
		end
	end
end

local function dissect_prm(buffer, pinfo, t_prime, payload_offset, payload_len, lnid)
	-- PRM: Byte 0: R(1), N(1), Reserved(3), SNR(3)
	if payload_len < 1 then
		pinfo.cols['info'] = "PRM (truncated)"
		return
	end
	local prm_r   = extract_bits(buffer(payload_offset, 1), 0, 1)
	local prm_n   = extract_bits(buffer(payload_offset, 1), 1, 1)
	local prm_snr = extract_bits(buffer(payload_offset, 1), 5, 3)
	local t_prm = t_prime:add(PRM_HDR, buffer(payload_offset, 1))
	t_prm:add(PRM_R,   buffer(payload_offset, 1), prm_r)
	t_prm:add(PRM_N,   buffer(payload_offset, 1), prm_n)
	t_prm:add(PRM_SNR, buffer(payload_offset, 1), prm_snr)
	local tPRM
	if prm_r == 0 and prm_n == 0 then
		tPRM = "REQ"
	elseif prm_r == 1 and prm_n == 0 then
		tPRM = "ACK"
	elseif prm_r == 1 and prm_n == 1 then
		tPRM = "REJ"
	end
	pinfo.cols['info'] = "PRM " .. (tPRM or "UNK") .. " LNID=" .. string.format("0x%04x", lnid) .. " SNR=" .. prm_snr
end

local function dissect_arq_subheader(buffer, t_prime, start_offset)
	local frame_len = buffer:len()
	if start_offset >= frame_len then return 0 end

	local offset = start_offset
	local byte0 = buffer(offset, 1):uint()
	local m      = extract_bits(buffer(offset, 1), 0, 1)
	local flush  = extract_bits(buffer(offset, 1), 1, 1)
	local pktid  = extract_bits(buffer(offset, 1), 2, 6)
	offset = offset + 1

	-- Determine total subheader length (for subtree range)
	local sh_start = start_offset
	local scan_off = start_offset
	local scan_m = extract_bits(buffer(scan_off, 1), 0, 1)
	scan_off = scan_off + 1
	local info_count = 0
	while scan_m == 1 and scan_off < frame_len and info_count < 64 do
		local info_byte_m = extract_bits(buffer(scan_off, 1), 0, 1)
		local info_byte_bit1 = extract_bits(buffer(scan_off, 1), 1, 1)
		-- ARQ.ACK has M=0 and bit1=0 — stops the chain
		-- ARQ.WIN has M=1 and bit1=0 — continues the chain
		-- ARQ.NACK has M=? and bit1=1
		scan_m = info_byte_m
		scan_off = scan_off + 1
		info_count = info_count + 1
	end
	local sh_len = scan_off - sh_start

	local t_arq = t_prime:add(ARQ_HDR, buffer(sh_start, sh_len))
	t_arq:add(ARQ_M,     buffer(sh_start, 1), m)
	t_arq:add(ARQ_FLUSH, buffer(sh_start, 1), flush)
	t_arq:add(ARQ_PKTID, buffer(sh_start, 1), pktid)

	-- Parse INFO bytes
	local info_off = start_offset + 1
	local prev_m = m
	local guard = 0
	while prev_m == 1 and info_off < frame_len and guard < 64 do
		local info_byte = buffer(info_off, 1)
		local info_m    = extract_bits(info_byte, 0, 1)
		local info_bit1 = extract_bits(info_byte, 1, 1)
		if info_bit1 == 1 then
			-- ARQ.NACK: M | 1 | NACKID[5:0]
			local nackid = extract_bits(info_byte, 2, 6)
			t_arq:add(ARQ_NACKID, info_byte, nackid)
			prev_m = info_m
		elseif info_m == 1 then
			-- ARQ.WIN: 1 | 0 | Res(1) | WINSIZE[4:0]
			local winsize = extract_bits(info_byte, 3, 5)
			t_arq:add(ARQ_WINSIZE, info_byte, winsize)
			prev_m = 1
		else
			-- ARQ.ACK: 0 | 0 | ACKID[5:0]
			local ackid = extract_bits(info_byte, 2, 6)
			t_arq:add(ARQ_ACKID, info_byte, ackid)
			prev_m = 0
		end
		info_off = info_off + 1
		guard = guard + 1
	end

	return sh_len
end

local function dissect_sar_header(buffer, t_prime, start_offset, payload_len)
	if payload_len < 1 or start_offset >= buffer:len() then
		return 0, payload_len
	end

	local sar_type = extract_bits(buffer(start_offset, 1), 0, 2)
	local t_sar = t_prime:add(SAR_HDR, buffer(start_offset, 1))
	t_sar:add(SAR_TYPE, buffer(start_offset, 1), sar_type)
	if sar_type == 0 then
		local nsegs = extract_bits(buffer(start_offset, 1), 2, 6)
		t_sar:add(SAR_NSEGS, buffer(start_offset, 1), nsegs)
	else
		local seq = extract_bits(buffer(start_offset, 1), 2, 6)
		t_sar:add(SAR_SEQ, buffer(start_offset, 1), seq)
	end

	local data_len = payload_len - 1
	if sar_type == 3 and data_len >= 4 then
		local crc_offset = start_offset + payload_len - 4
		t_prime:add(SAR_CRC, buffer(crc_offset, 4))
		data_len = data_len - 4
	end

	if data_len < 0 then
		data_len = 0
	end

	return 1, data_len
end

local function dissect_general_pdu(buffer, pinfo, t_prime)
	local frame_len = buffer:len()
	local ver = extract_bits(buffer(0,1), 0, 2)
	local min_frame = (ver == 0) and 13 or 14
	if frame_len < min_frame then
		pinfo.cols['info'] = "General PDU (truncated)"
		return
	end

	local generic_header = buffer(0,3)
	local prime_ht = extract_bits(generic_header, 2, 2)
	local hdr_reserved = extract_bits(generic_header, 4, 5)
	local direction = extract_bits(generic_header, 9, 1)
	local level = extract_bits(generic_header, 10, 6)

	-- Generic MAC Header (identical layout for both versions)
	local t_hdr = t_prime:add(HDR, buffer(0,3))
	t_hdr:add(HT, buffer(0,1), prime_ht)
	t_hdr:add(HDR_RESERVED, buffer(0,2), hdr_reserved)
	t_hdr:add(HDR_DO, buffer(1,1), direction)
	t_hdr:add(HDR_LEVEL, buffer(1,1), level)
	t_hdr:add(HDR_HCS, buffer(2,1))

	local prio, c, lcid_or_ctype, sid, lnid, pkt_len, nad
	local payload_offset

	if ver == 0 then
		-- PRIME v1.3.6 Packet Header (6 bytes)
		-- Reserved(3), NAD(1), PRIO(2), C(1), LCID/CTYPE(9), SID(8), LNID(14), SPAD(1), LEN(9)
		local packet_header = buffer(3,6)
		local pkt_reserved = extract_bits(packet_header, 0, 3)
		nad = extract_bits(packet_header, 3, 1)
		prio = extract_bits(packet_header, 4, 2)
		c = extract_bits(packet_header, 6, 1)
		lcid_or_ctype = extract_bits(packet_header, 7, 9)
		sid = extract_bits(packet_header, 16, 8)
		lnid = extract_bits(packet_header, 24, 14)
		local spad = extract_bits(packet_header, 38, 1)
		pkt_len = extract_bits(packet_header, 39, 9)
		payload_offset = 9

		local t_pkt = t_prime:add(PKT, buffer(3,6))
		t_pkt:add(PKT_RESERVED, buffer(3,1), pkt_reserved)
		t_pkt:add(PKT_NAD, buffer(3,1), nad)
		t_pkt:add(PKT_PRIO, buffer(3,1), prio)
		t_pkt:add(PKT_C, buffer(3,1), c)
		if c == 1 then
			t_pkt:add(PKT_CTYPE, buffer(3,2), lcid_or_ctype)
		else
			t_pkt:add(PKT_LCID, buffer(3,2), lcid_or_ctype)
		end
		t_pkt:add(PKT_SID, buffer(5,1), sid)
		t_pkt:add(PKT_LNID, buffer(6,2), lnid)
		t_pkt:add(PKT_SPAD, buffer(7,1), spad)
		t_pkt:add(PKT_LEN, buffer(7,2), pkt_len)
	else
		-- PRIME v1.4 Packet Header (7 bytes)
		-- RM(4), PRIO(2), C(1), LCID/CTYPE(9), SID(8), LNID(14), Reserved(1), LEN(9),
		-- NAD(1), TREF(1), ARQ(1), PSH(1), Reserved(4)
		local packet_header = buffer(3,7)
		local rm = extract_bits(packet_header, 0, 4)
		prio = extract_bits(packet_header, 4, 2)
		c = extract_bits(packet_header, 6, 1)
		lcid_or_ctype = extract_bits(packet_header, 7, 9)
		sid = extract_bits(packet_header, 16, 8)
		lnid = extract_bits(packet_header, 24, 14)
		local pkt_reserved14 = extract_bits(packet_header, 38, 1)
		pkt_len = extract_bits(packet_header, 39, 9)
		nad = extract_bits(packet_header, 48, 1)
		local tref = extract_bits(packet_header, 49, 1)
		local pkt_arq = extract_bits(packet_header, 50, 1)
		local psh = extract_bits(packet_header, 51, 1)
		payload_offset = 10

		local t_pkt = t_prime:add(PKT, buffer(3,7))
		t_pkt:add(PKT_RM, buffer(3,1), rm)
		t_pkt:add(PKT_PRIO, buffer(3,1), prio)
		t_pkt:add(PKT_C, buffer(3,1), c)
		if c == 1 then
			t_pkt:add(PKT_CTYPE, buffer(3,2), lcid_or_ctype)
		else
			t_pkt:add(PKT_LCID, buffer(3,2), lcid_or_ctype)
		end
		t_pkt:add(PKT_SID, buffer(5,1), sid)
		t_pkt:add(PKT_LNID, buffer(6,2), lnid)
		t_pkt:add(PKT_RESERVED, buffer(7,1), pkt_reserved14)
		t_pkt:add(PKT_LEN, buffer(7,2), pkt_len)
		t_pkt:add(PKT_NAD, buffer(9,1), nad)
		t_pkt:add(PKT_TREF, buffer(9,1), tref)
		t_pkt:add(PKT_ARQ, buffer(9,1), pkt_arq)
		t_pkt:add(PKT_PSH, buffer(9,1), psh)
		if pkt_arq == 1 and c == 0 then
			local arq_bytes = dissect_arq_subheader(buffer, t_prime, payload_offset)
			payload_offset = payload_offset + arq_bytes
		end
	end

	local available_payload_len = math.max(frame_len - payload_offset - 4, 0)
	local payload_len = math.min(pkt_len, available_payload_len)

	if c == 0 then
		local sar_bytes = 0
		if payload_len > 0 then
			sar_bytes, payload_len = dissect_sar_header(buffer, t_prime, payload_offset, payload_len)
			payload_offset = payload_offset + sar_bytes
		end
		if payload_len > 0 then
			t_prime:add(ControlData, buffer(payload_offset,payload_len))
		end
		if direction == 0 then
			pinfo.cols['info'] = "DATA_S"
		else
			pinfo.cols['info'] = "DATA_B"
		end
	elseif lcid_or_ctype == 1 then
		dissect_reg(buffer, pinfo, t_prime, payload_offset, payload_len, ver, direction, lnid)
	elseif lcid_or_ctype == 2 then
		dissect_con(buffer, pinfo, t_prime, payload_offset, payload_len, direction, lnid)
	elseif lcid_or_ctype == 3 then
		dissect_pro(buffer, pinfo, t_prime, payload_offset, payload_len, ver, direction, lnid)
	elseif lcid_or_ctype == 4 then
		dissect_bsi(buffer, pinfo, t_prime, payload_offset, payload_len, direction, lnid)
	elseif lcid_or_ctype == 7 then
		dissect_alv(buffer, pinfo, t_prime, payload_offset, payload_len, ver, direction, lnid)
	elseif lcid_or_ctype == 9 then
		dissect_prm(buffer, pinfo, t_prime, payload_offset, payload_len, lnid)
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
		dissect_general_pdu(buffer, pinfo, t_prime, frame_len, prime_ht)
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
