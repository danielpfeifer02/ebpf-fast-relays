#include <stdint.h>

#define PADDING_FRAME 0x00
#define PING_FRAME 0x01
#define ACK_FRAME 0x02
#define ACK_ECN_FRAME 0x03
#define RESET_STREAM_FRAME 0x04
#define STOP_SENDING_FRAME 0x05
#define CRYPTO_FRAME 0x06
#define NEW_TOKEN_FRAME 0x07

#define STREAM_FRAME 0x08
#define OFF_BIT 0x04
#define LEN_BIT 0x02
#define FIN_BIT 0x01
#define STREAM_WITH_OFF (STREAM_FRAME | OFF_BIT)
#define STREAM_WITH_LEN (STREAM_FRAME | LEN_BIT)
#define STREAM_WITH_FIN (STREAM_FRAME | FIN_BIT)
#define STREAM_WITH_OFF_LEN (STREAM_FRAME | OFF_BIT | LEN_BIT)
#define STREAM_WITH_OFF_FIN (STREAM_FRAME | OFF_BIT | FIN_BIT)
#define STREAM_WITH_LEN_FIN (STREAM_FRAME | LEN_BIT | FIN_BIT)
#define STREAM_WITH_OFF_LEN_FIN (STREAM_FRAME | OFF_BIT | LEN_BIT | FIN_BIT)

#define MAX_DATA_FRAME 0x10
#define MAX_STREAM_DATA_FRAME 0x11
#define DATA_BLOCKED_FRAME 0x14
#define STREAM_DATA_BLOCKED_FRAME 0x15
#define NEW_CONNECTION_ID_FRAME 0x18
#define RETIRE_CONNECTION_ID_FRAME 0x19
#define PATH_CHALLENGE_FRAME 0x1a
#define PATH_RESPONSE_FRAME 0x1b
#define HANDSHAKE_DONE_FRAME 0x1e

#define INVALID_FRAME 0xff

// https://datatracker.ietf.org/doc/html/rfc9000#frames
uint8_t get_number_of_var_ints_of_frame(uint64_t frame_id) {
        switch (frame_id) {
                /*
                PADDING Frame {
                  Type (i) = 0x00,
                }
                */
                case PADDING_FRAME:
                        return 1;

                /*
                PING Frame {
                  Type (i) = 0x01,
                }
                */
                case PING_FRAME:
                        return 1;

                /*
                ACK Frame {
                  Type (i) = 0x02..0x03,
                  Largest Acknowledged (i),
                  ACK Delay (i),
                  ACK Range Count (i),
                  First ACK Range (i),
                  ACK Range (..) ...,
                  [ECN Counts (..)],
                }
                ACK Range {
                  Gap (i),
                  ACK Range Length (i),
                }
                ECN Counts {
                  ECT0 Count (i),
                  ECT1 Count (i),
                  ECN-CE Count (i),
                }
                */
                case ACK_FRAME:
                        return 5;
                case ACK_ECN_FRAME: 
                        return 8; //TODO: ACK Range (has two varints) and ECN Counts (has three varints???
                
                /*
                RESET_STREAM Frame {
                  Type (i) = 0x04,
                  Stream ID (i),
                  Application Protocol Error Code (i),
                  Final Size (i),
                }
                */
                case RESET_STREAM_FRAME:
                        return 4;
                
                /*
                STOP_SENDING Frame {
                  Type (i) = 0x05,
                  Stream ID (i),
                  Application Protocol Error Code (i),
                }
                */
                case STOP_SENDING_FRAME:
                        return 3;
                
                /*
                CRYPTO Frame {
                  Type (i) = 0x06,
                  Offset (i),
                  Length (i),
                  Crypto Data (..),
                }
                */
                case CRYPTO_FRAME:
                        return 3; //TODO: plus crypto data
                
                /*
                NEW_TOKEN Frame {
                  Type (i) = 0x07,
                  Token Length (i),
                  Token (..),
                }
                */
                case NEW_TOKEN_FRAME:
                        return 2; //TODO: second one is token length

                /*
                STREAM Frame {
                  Type (i) = 0x08..0x0f,
                  Stream ID (i),
                  [Offset (i)],
                  [Length (i)],
                  Stream Data (..),
                }
                */
                case STREAM_FRAME:
                case STREAM_WITH_FIN:
                        return 2;
                case STREAM_WITH_LEN:
                case STREAM_WITH_OFF:
                case STREAM_WITH_LEN_FIN:
                case STREAM_WITH_OFF_FIN:
                        return 3;
                case STREAM_WITH_OFF_LEN:
                case STREAM_WITH_OFF_LEN_FIN:
                        return 4;
                
                /*
                MAX_DATA Frame {
                  Type (i) = 0x10,
                  Maximum Data (i),
                }
                */
                case MAX_DATA_FRAME:
                        return 2;
                
                /*
                MAX_STREAM_DATA Frame {
                  Type (i) = 0x11,
                  Stream ID (i),
                  Maximum Stream Data (i),
                }
                */
                case MAX_STREAM_DATA_FRAME:
                        return 3;
                
                /*
                MAX_STREAMS Frame {
                  Type (i) = 0x12..0x13,
                  Maximum Streams (i),
                }
                */
                case 0x12: // MAX_STREAMS
                case 0x13:
                        return 2;
                
                /*
                DATA_BLOCKED Frame {
                  Type (i) = 0x14,
                  Maximum Data (i),
                }
                */
                case DATA_BLOCKED_FRAME:
                        return 2;
                
                /*
                STREAM_DATA_BLOCKED Frame {
                  Type (i) = 0x15,
                  Stream ID (i),
                  Maximum Stream Data (i),
                }
                */
                case STREAM_DATA_BLOCKED_FRAME: 
                        return 3;
                
                /*
                STREAMS_BLOCKED Frame {
                  Type (i) = 0x16..0x17,
                  Maximum Streams (i),
                }
                */
                case 0x16: // STREAMS_BLOCKED
                case 0x17:
                        return 2;
                
                /*
                NEW_CONNECTION_ID Frame {
                  Type (i) = 0x18,
                  Sequence Number (i),
                  Retire Prior To (i),
                  Length (8),
                  Connection ID (8..160),
                  Stateless Reset Token (128),
                }
                */
                case NEW_CONNECTION_ID_FRAME:
                        return 3;
                
                /*
                RETIRE_CONNECTION_ID Frame {
                  Type (i) = 0x19,
                  Sequence Number (i),
                }
                */
                case RETIRE_CONNECTION_ID_FRAME:
                        return 2;
                
                /*
                PATH_CHALLENGE Frame {
                  Type (i) = 0x1a,
                  Data (64),
                }
                */
                case PATH_CHALLENGE_FRAME:
                        return 1;
                
                /*
                PATH_RESPONSE Frame {
                  Type (i) = 0x1b,
                  Data (64),
                }
                */
                case PATH_RESPONSE_FRAME:
                        return 1;
                
                /*
                CONNECTION_CLOSE Frame {
                  Type (i) = 0x1c..0x1d,
                  Error Code (i),
                  [Frame Type (i)],
                  Reason Phrase Length (i),
                  Reason Phrase (..),
                }
                */
                case 0x1c: // CONNECTION_CLOSE
                case 0x1d:
                        return 3; //TODO: when is frame type there?
                
                /*
                HANDSHAKE_DONE Frame {
                  Type (i) = 0x1e,
                }       
                */
                case HANDSHAKE_DONE_FRAME:
                        return 1;       
                
                /*
                  In this case the frame read is not valid
                */
                default: // unknown frame
                        return INVALID_FRAME;
        }
}