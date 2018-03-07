set(GTPV2C_DIR  ${CMAKE_CURRENT_SOURCE_DIR}/nwgtpv2c-0.11/src)
add_library(GTPV2C
    ${GTPV2C_DIR}/NwGtpv2cTrxn.c
    ${GTPV2C_DIR}/NwGtpv2cTunnel.c
    ${GTPV2C_DIR}/NwGtpv2cMsg.c
    ${GTPV2C_DIR}/NwGtpv2cMsgIeParseInfo.c
    ${GTPV2C_DIR}/NwGtpv2cMsgParser.c
    ${GTPV2C_DIR}/NwGtpv2c.c
    )


# common_defs.h for return values
include_directories(${SRC_TOP_DIR}/common)
# log.h
include_directories(${SRC_TOP_DIR}/utils)
include_directories(${SRC_TOP_DIR}/utils/msc)
include_directories(${SRC_TOP_DIR}/utils/bstr)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/nwgtpv2c-0.11/include/)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/nwgtpv2c-0.11/shared/)
