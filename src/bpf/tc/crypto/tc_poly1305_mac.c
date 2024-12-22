#include <stdint.h>

#include "tc_crypto_defines.c"
#include "tc_crypto_structs.c"
#include "tc_mac_update_from_asm.c"
#include "../main/tc_common.c"

#define REPEAT_16(X) X X X X X X X X X X X X X X X X

#define MAX_LINEARIZED_PADDED_DATA_SIZE (MAX_ADDITIONAL_DATA_SIZE + 15 + MAX_PAYLOAD_SIZE + 15 + 8 + 8)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, uint32_t);
    __type(value, uint64_t);
    __uint(max_entries, MAX_LINEARIZED_PADDED_DATA_SIZE);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} linearized_padded_data SEC(".maps");

struct my_uint128_t {
    uint64_t lo;
    uint64_t hi;
};

struct my_uint192_t {
    uint64_t lo;
    uint64_t mid;
    uint64_t hi;
};


const uint64_t mod_lut[768] = {
0x0000000000000000, 0x0000000000000000, 0x0000000000000001, // for k = 1
0x0000000000000000, 0x0000000000000000, 0x0000000000000002, // for k = 2
0x0000000000000000, 0x0000000000000000, 0x0000000000000004, // for k = 4
0x0000000000000000, 0x0000000000000000, 0x0000000000000008, // for k = 8
0x0000000000000000, 0x0000000000000000, 0x0000000000000010, // for k = 16
0x0000000000000000, 0x0000000000000000, 0x0000000000000020, // for k = 32
0x0000000000000000, 0x0000000000000000, 0x0000000000000040, // for k = 64
0x0000000000000000, 0x0000000000000000, 0x0000000000000080, // for k = 128
0x0000000000000000, 0x0000000000000000, 0x0000000000000100, // for k = 256
0x0000000000000000, 0x0000000000000000, 0x0000000000000200, // for k = 512
0x0000000000000000, 0x0000000000000000, 0x0000000000000400, // for k = 1024
0x0000000000000000, 0x0000000000000000, 0x0000000000000800, // for k = 2048
0x0000000000000000, 0x0000000000000000, 0x0000000000001000, // for k = 4096
0x0000000000000000, 0x0000000000000000, 0x0000000000002000, // for k = 8192
0x0000000000000000, 0x0000000000000000, 0x0000000000004000, // for k = 16384
0x0000000000000000, 0x0000000000000000, 0x0000000000008000, // for k = 32768
0x0000000000000000, 0x0000000000000000, 0x0000000000010000, // for k = 65536
0x0000000000000000, 0x0000000000000000, 0x0000000000020000, // for k = 131072
0x0000000000000000, 0x0000000000000000, 0x0000000000040000, // for k = 262144
0x0000000000000000, 0x0000000000000000, 0x0000000000080000, // for k = 524288
0x0000000000000000, 0x0000000000000000, 0x0000000000100000, // for k = 1048576
0x0000000000000000, 0x0000000000000000, 0x0000000000200000, // for k = 2097152
0x0000000000000000, 0x0000000000000000, 0x0000000000400000, // for k = 4194304
0x0000000000000000, 0x0000000000000000, 0x0000000000800000, // for k = 8388608
0x0000000000000000, 0x0000000000000000, 0x0000000001000000, // for k = 16777216
0x0000000000000000, 0x0000000000000000, 0x0000000002000000, // for k = 33554432
0x0000000000000000, 0x0000000000000000, 0x0000000004000000, // for k = 67108864
0x0000000000000000, 0x0000000000000000, 0x0000000008000000, // for k = 134217728
0x0000000000000000, 0x0000000000000000, 0x0000000010000000, // for k = 268435456
0x0000000000000000, 0x0000000000000000, 0x0000000020000000, // for k = 536870912
0x0000000000000000, 0x0000000000000000, 0x0000000040000000, // for k = 1073741824
0x0000000000000000, 0x0000000000000000, 0x0000000080000000, // for k = 2147483648
0x0000000000000000, 0x0000000000000000, 0x0000000100000000, // for k = 4294967296
0x0000000000000000, 0x0000000000000000, 0x0000000200000000, // for k = 8589934592
0x0000000000000000, 0x0000000000000000, 0x0000000400000000, // for k = 17179869184
0x0000000000000000, 0x0000000000000000, 0x0000000800000000, // for k = 34359738368
0x0000000000000000, 0x0000000000000000, 0x0000001000000000, // for k = 68719476736
0x0000000000000000, 0x0000000000000000, 0x0000002000000000, // for k = 137438953472
0x0000000000000000, 0x0000000000000000, 0x0000004000000000, // for k = 274877906944
0x0000000000000000, 0x0000000000000000, 0x0000008000000000, // for k = 549755813888
0x0000000000000000, 0x0000000000000000, 0x0000010000000000, // for k = 1099511627776
0x0000000000000000, 0x0000000000000000, 0x0000020000000000, // for k = 2199023255552
0x0000000000000000, 0x0000000000000000, 0x0000040000000000, // for k = 4398046511104
0x0000000000000000, 0x0000000000000000, 0x0000080000000000, // for k = 8796093022208
0x0000000000000000, 0x0000000000000000, 0x0000100000000000, // for k = 17592186044416
0x0000000000000000, 0x0000000000000000, 0x0000200000000000, // for k = 35184372088832
0x0000000000000000, 0x0000000000000000, 0x0000400000000000, // for k = 70368744177664
0x0000000000000000, 0x0000000000000000, 0x0000800000000000, // for k = 140737488355328
0x0000000000000000, 0x0000000000000000, 0x0001000000000000, // for k = 281474976710656
0x0000000000000000, 0x0000000000000000, 0x0002000000000000, // for k = 562949953421312
0x0000000000000000, 0x0000000000000000, 0x0004000000000000, // for k = 1125899906842624
0x0000000000000000, 0x0000000000000000, 0x0008000000000000, // for k = 2251799813685248
0x0000000000000000, 0x0000000000000000, 0x0010000000000000, // for k = 4503599627370496
0x0000000000000000, 0x0000000000000000, 0x0020000000000000, // for k = 9007199254740992
0x0000000000000000, 0x0000000000000000, 0x0040000000000000, // for k = 18014398509481984
0x0000000000000000, 0x0000000000000000, 0x0080000000000000, // for k = 36028797018963968
0x0000000000000000, 0x0000000000000000, 0x0100000000000000, // for k = 72057594037927936
0x0000000000000000, 0x0000000000000000, 0x0200000000000000, // for k = 144115188075855872
0x0000000000000000, 0x0000000000000000, 0x0400000000000000, // for k = 288230376151711744
0x0000000000000000, 0x0000000000000000, 0x0800000000000000, // for k = 576460752303423488
0x0000000000000000, 0x0000000000000000, 0x1000000000000000, // for k = 1152921504606846976
0x0000000000000000, 0x0000000000000000, 0x2000000000000000, // for k = 2305843009213693952
0x0000000000000000, 0x0000000000000000, 0x4000000000000000, // for k = 4611686018427387904
0x0000000000000000, 0x0000000000000000, 0x8000000000000000, // for k = 9223372036854775808
0x0000000000000000, 0x0000000000000001, 0x0000000000000000, // for k = 18446744073709551616
0x0000000000000000, 0x0000000000000002, 0x0000000000000000, // for k = 36893488147419103232
0x0000000000000000, 0x0000000000000004, 0x0000000000000000, // for k = 73786976294838206464
0x0000000000000000, 0x0000000000000008, 0x0000000000000000, // for k = 147573952589676412928
0x0000000000000000, 0x0000000000000010, 0x0000000000000000, // for k = 295147905179352825856
0x0000000000000000, 0x0000000000000020, 0x0000000000000000, // for k = 590295810358705651712
0x0000000000000000, 0x0000000000000040, 0x0000000000000000, // for k = 1180591620717411303424
0x0000000000000000, 0x0000000000000080, 0x0000000000000000, // for k = 2361183241434822606848
0x0000000000000000, 0x0000000000000100, 0x0000000000000000, // for k = 4722366482869645213696
0x0000000000000000, 0x0000000000000200, 0x0000000000000000, // for k = 9444732965739290427392
0x0000000000000000, 0x0000000000000400, 0x0000000000000000, // for k = 18889465931478580854784
0x0000000000000000, 0x0000000000000800, 0x0000000000000000, // for k = 37778931862957161709568
0x0000000000000000, 0x0000000000001000, 0x0000000000000000, // for k = 75557863725914323419136
0x0000000000000000, 0x0000000000002000, 0x0000000000000000, // for k = 151115727451828646838272
0x0000000000000000, 0x0000000000004000, 0x0000000000000000, // for k = 302231454903657293676544
0x0000000000000000, 0x0000000000008000, 0x0000000000000000, // for k = 604462909807314587353088
0x0000000000000000, 0x0000000000010000, 0x0000000000000000, // for k = 1208925819614629174706176
0x0000000000000000, 0x0000000000020000, 0x0000000000000000, // for k = 2417851639229258349412352
0x0000000000000000, 0x0000000000040000, 0x0000000000000000, // for k = 4835703278458516698824704
0x0000000000000000, 0x0000000000080000, 0x0000000000000000, // for k = 9671406556917033397649408
0x0000000000000000, 0x0000000000100000, 0x0000000000000000, // for k = 19342813113834066795298816
0x0000000000000000, 0x0000000000200000, 0x0000000000000000, // for k = 38685626227668133590597632
0x0000000000000000, 0x0000000000400000, 0x0000000000000000, // for k = 77371252455336267181195264
0x0000000000000000, 0x0000000000800000, 0x0000000000000000, // for k = 154742504910672534362390528
0x0000000000000000, 0x0000000001000000, 0x0000000000000000, // for k = 309485009821345068724781056
0x0000000000000000, 0x0000000002000000, 0x0000000000000000, // for k = 618970019642690137449562112
0x0000000000000000, 0x0000000004000000, 0x0000000000000000, // for k = 1237940039285380274899124224
0x0000000000000000, 0x0000000008000000, 0x0000000000000000, // for k = 2475880078570760549798248448
0x0000000000000000, 0x0000000010000000, 0x0000000000000000, // for k = 4951760157141521099596496896
0x0000000000000000, 0x0000000020000000, 0x0000000000000000, // for k = 9903520314283042199192993792
0x0000000000000000, 0x0000000040000000, 0x0000000000000000, // for k = 19807040628566084398385987584
0x0000000000000000, 0x0000000080000000, 0x0000000000000000, // for k = 39614081257132168796771975168
0x0000000000000000, 0x0000000100000000, 0x0000000000000000, // for k = 79228162514264337593543950336
0x0000000000000000, 0x0000000200000000, 0x0000000000000000, // for k = 158456325028528675187087900672
0x0000000000000000, 0x0000000400000000, 0x0000000000000000, // for k = 316912650057057350374175801344
0x0000000000000000, 0x0000000800000000, 0x0000000000000000, // for k = 633825300114114700748351602688
0x0000000000000000, 0x0000001000000000, 0x0000000000000000, // for k = 1267650600228229401496703205376
0x0000000000000000, 0x0000002000000000, 0x0000000000000000, // for k = 2535301200456458802993406410752
0x0000000000000000, 0x0000004000000000, 0x0000000000000000, // for k = 5070602400912917605986812821504
0x0000000000000000, 0x0000008000000000, 0x0000000000000000, // for k = 10141204801825835211973625643008
0x0000000000000000, 0x0000010000000000, 0x0000000000000000, // for k = 20282409603651670423947251286016
0x0000000000000000, 0x0000020000000000, 0x0000000000000000, // for k = 40564819207303340847894502572032
0x0000000000000000, 0x0000040000000000, 0x0000000000000000, // for k = 81129638414606681695789005144064
0x0000000000000000, 0x0000080000000000, 0x0000000000000000, // for k = 162259276829213363391578010288128
0x0000000000000000, 0x0000100000000000, 0x0000000000000000, // for k = 324518553658426726783156020576256
0x0000000000000000, 0x0000200000000000, 0x0000000000000000, // for k = 649037107316853453566312041152512
0x0000000000000000, 0x0000400000000000, 0x0000000000000000, // for k = 1298074214633706907132624082305024
0x0000000000000000, 0x0000800000000000, 0x0000000000000000, // for k = 2596148429267413814265248164610048
0x0000000000000000, 0x0001000000000000, 0x0000000000000000, // for k = 5192296858534827628530496329220096
0x0000000000000000, 0x0002000000000000, 0x0000000000000000, // for k = 10384593717069655257060992658440192
0x0000000000000000, 0x0004000000000000, 0x0000000000000000, // for k = 20769187434139310514121985316880384
0x0000000000000000, 0x0008000000000000, 0x0000000000000000, // for k = 41538374868278621028243970633760768
0x0000000000000000, 0x0010000000000000, 0x0000000000000000, // for k = 83076749736557242056487941267521536
0x0000000000000000, 0x0020000000000000, 0x0000000000000000, // for k = 166153499473114484112975882535043072
0x0000000000000000, 0x0040000000000000, 0x0000000000000000, // for k = 332306998946228968225951765070086144
0x0000000000000000, 0x0080000000000000, 0x0000000000000000, // for k = 664613997892457936451903530140172288
0x0000000000000000, 0x0100000000000000, 0x0000000000000000, // for k = 1329227995784915872903807060280344576
0x0000000000000000, 0x0200000000000000, 0x0000000000000000, // for k = 2658455991569831745807614120560689152
0x0000000000000000, 0x0400000000000000, 0x0000000000000000, // for k = 5316911983139663491615228241121378304
0x0000000000000000, 0x0800000000000000, 0x0000000000000000, // for k = 10633823966279326983230456482242756608
0x0000000000000000, 0x1000000000000000, 0x0000000000000000, // for k = 21267647932558653966460912964485513216
0x0000000000000000, 0x2000000000000000, 0x0000000000000000, // for k = 42535295865117307932921825928971026432
0x0000000000000000, 0x4000000000000000, 0x0000000000000000, // for k = 85070591730234615865843651857942052864
0x0000000000000000, 0x8000000000000000, 0x0000000000000000, // for k = 170141183460469231731687303715884105728
0x0000000000000001, 0x0000000000000000, 0x0000000000000000, // for k = 340282366920938463463374607431768211456
0x0000000000000002, 0x0000000000000000, 0x0000000000000000, // for k = 680564733841876926926749214863536422912
0x0000000000000000, 0x0000000000000000, 0x0000000000000005, // for k = 1361129467683753853853498429727072845824
0x0000000000000000, 0x0000000000000000, 0x000000000000000a, // for k = 2722258935367507707706996859454145691648
0x0000000000000000, 0x0000000000000000, 0x0000000000000014, // for k = 5444517870735015415413993718908291383296
0x0000000000000000, 0x0000000000000000, 0x0000000000000028, // for k = 10889035741470030830827987437816582766592
0x0000000000000000, 0x0000000000000000, 0x0000000000000050, // for k = 21778071482940061661655974875633165533184
0x0000000000000000, 0x0000000000000000, 0x00000000000000a0, // for k = 43556142965880123323311949751266331066368
0x0000000000000000, 0x0000000000000000, 0x0000000000000140, // for k = 87112285931760246646623899502532662132736
0x0000000000000000, 0x0000000000000000, 0x0000000000000280, // for k = 174224571863520493293247799005065324265472
0x0000000000000000, 0x0000000000000000, 0x0000000000000500, // for k = 348449143727040986586495598010130648530944
0x0000000000000000, 0x0000000000000000, 0x0000000000000a00, // for k = 696898287454081973172991196020261297061888
0x0000000000000000, 0x0000000000000000, 0x0000000000001400, // for k = 1393796574908163946345982392040522594123776
0x0000000000000000, 0x0000000000000000, 0x0000000000002800, // for k = 2787593149816327892691964784081045188247552
0x0000000000000000, 0x0000000000000000, 0x0000000000005000, // for k = 5575186299632655785383929568162090376495104
0x0000000000000000, 0x0000000000000000, 0x000000000000a000, // for k = 11150372599265311570767859136324180752990208
0x0000000000000000, 0x0000000000000000, 0x0000000000014000, // for k = 22300745198530623141535718272648361505980416
0x0000000000000000, 0x0000000000000000, 0x0000000000028000, // for k = 44601490397061246283071436545296723011960832
0x0000000000000000, 0x0000000000000000, 0x0000000000050000, // for k = 89202980794122492566142873090593446023921664
0x0000000000000000, 0x0000000000000000, 0x00000000000a0000, // for k = 178405961588244985132285746181186892047843328
0x0000000000000000, 0x0000000000000000, 0x0000000000140000, // for k = 356811923176489970264571492362373784095686656
0x0000000000000000, 0x0000000000000000, 0x0000000000280000, // for k = 713623846352979940529142984724747568191373312
0x0000000000000000, 0x0000000000000000, 0x0000000000500000, // for k = 1427247692705959881058285969449495136382746624
0x0000000000000000, 0x0000000000000000, 0x0000000000a00000, // for k = 2854495385411919762116571938898990272765493248
0x0000000000000000, 0x0000000000000000, 0x0000000001400000, // for k = 5708990770823839524233143877797980545530986496
0x0000000000000000, 0x0000000000000000, 0x0000000002800000, // for k = 11417981541647679048466287755595961091061972992
0x0000000000000000, 0x0000000000000000, 0x0000000005000000, // for k = 22835963083295358096932575511191922182123945984
0x0000000000000000, 0x0000000000000000, 0x000000000a000000, // for k = 45671926166590716193865151022383844364247891968
0x0000000000000000, 0x0000000000000000, 0x0000000014000000, // for k = 91343852333181432387730302044767688728495783936
0x0000000000000000, 0x0000000000000000, 0x0000000028000000, // for k = 182687704666362864775460604089535377456991567872
0x0000000000000000, 0x0000000000000000, 0x0000000050000000, // for k = 365375409332725729550921208179070754913983135744
0x0000000000000000, 0x0000000000000000, 0x00000000a0000000, // for k = 730750818665451459101842416358141509827966271488
0x0000000000000000, 0x0000000000000000, 0x0000000140000000, // for k = 1461501637330902918203684832716283019655932542976
0x0000000000000000, 0x0000000000000000, 0x0000000280000000, // for k = 2923003274661805836407369665432566039311865085952
0x0000000000000000, 0x0000000000000000, 0x0000000500000000, // for k = 5846006549323611672814739330865132078623730171904
0x0000000000000000, 0x0000000000000000, 0x0000000a00000000, // for k = 11692013098647223345629478661730264157247460343808
0x0000000000000000, 0x0000000000000000, 0x0000001400000000, // for k = 23384026197294446691258957323460528314494920687616
0x0000000000000000, 0x0000000000000000, 0x0000002800000000, // for k = 46768052394588893382517914646921056628989841375232
0x0000000000000000, 0x0000000000000000, 0x0000005000000000, // for k = 93536104789177786765035829293842113257979682750464
0x0000000000000000, 0x0000000000000000, 0x000000a000000000, // for k = 187072209578355573530071658587684226515959365500928
0x0000000000000000, 0x0000000000000000, 0x0000014000000000, // for k = 374144419156711147060143317175368453031918731001856
0x0000000000000000, 0x0000000000000000, 0x0000028000000000, // for k = 748288838313422294120286634350736906063837462003712
0x0000000000000000, 0x0000000000000000, 0x0000050000000000, // for k = 1496577676626844588240573268701473812127674924007424
0x0000000000000000, 0x0000000000000000, 0x00000a0000000000, // for k = 2993155353253689176481146537402947624255349848014848
0x0000000000000000, 0x0000000000000000, 0x0000140000000000, // for k = 5986310706507378352962293074805895248510699696029696
0x0000000000000000, 0x0000000000000000, 0x0000280000000000, // for k = 11972621413014756705924586149611790497021399392059392
0x0000000000000000, 0x0000000000000000, 0x0000500000000000, // for k = 23945242826029513411849172299223580994042798784118784
0x0000000000000000, 0x0000000000000000, 0x0000a00000000000, // for k = 47890485652059026823698344598447161988085597568237568
0x0000000000000000, 0x0000000000000000, 0x0001400000000000, // for k = 95780971304118053647396689196894323976171195136475136
0x0000000000000000, 0x0000000000000000, 0x0002800000000000, // for k = 191561942608236107294793378393788647952342390272950272
0x0000000000000000, 0x0000000000000000, 0x0005000000000000, // for k = 383123885216472214589586756787577295904684780545900544
0x0000000000000000, 0x0000000000000000, 0x000a000000000000, // for k = 766247770432944429179173513575154591809369561091801088
0x0000000000000000, 0x0000000000000000, 0x0014000000000000, // for k = 1532495540865888858358347027150309183618739122183602176
0x0000000000000000, 0x0000000000000000, 0x0028000000000000, // for k = 3064991081731777716716694054300618367237478244367204352
0x0000000000000000, 0x0000000000000000, 0x0050000000000000, // for k = 6129982163463555433433388108601236734474956488734408704
0x0000000000000000, 0x0000000000000000, 0x00a0000000000000, // for k = 12259964326927110866866776217202473468949912977468817408
0x0000000000000000, 0x0000000000000000, 0x0140000000000000, // for k = 24519928653854221733733552434404946937899825954937634816
0x0000000000000000, 0x0000000000000000, 0x0280000000000000, // for k = 49039857307708443467467104868809893875799651909875269632
0x0000000000000000, 0x0000000000000000, 0x0500000000000000, // for k = 98079714615416886934934209737619787751599303819750539264
0x0000000000000000, 0x0000000000000000, 0x0a00000000000000, // for k = 196159429230833773869868419475239575503198607639501078528
0x0000000000000000, 0x0000000000000000, 0x1400000000000000, // for k = 392318858461667547739736838950479151006397215279002157056
0x0000000000000000, 0x0000000000000000, 0x2800000000000000, // for k = 784637716923335095479473677900958302012794430558004314112
0x0000000000000000, 0x0000000000000000, 0x5000000000000000, // for k = 1569275433846670190958947355801916604025588861116008628224
0x0000000000000000, 0x0000000000000000, 0xa000000000000000, // for k = 3138550867693340381917894711603833208051177722232017256448
0x0000000000000000, 0x0000000000000001, 0x4000000000000000, // for k = 6277101735386680763835789423207666416102355444464034512896
0x0000000000000000, 0x0000000000000002, 0x8000000000000000, // for k = 12554203470773361527671578846415332832204710888928069025792
0x0000000000000000, 0x0000000000000005, 0x0000000000000000, // for k = 25108406941546723055343157692830665664409421777856138051584
0x0000000000000000, 0x000000000000000a, 0x0000000000000000, // for k = 50216813883093446110686315385661331328818843555712276103168
0x0000000000000000, 0x0000000000000014, 0x0000000000000000, // for k = 100433627766186892221372630771322662657637687111424552206336
0x0000000000000000, 0x0000000000000028, 0x0000000000000000, // for k = 200867255532373784442745261542645325315275374222849104412672
0x0000000000000000, 0x0000000000000050, 0x0000000000000000, // for k = 401734511064747568885490523085290650630550748445698208825344
0x0000000000000000, 0x00000000000000a0, 0x0000000000000000, // for k = 803469022129495137770981046170581301261101496891396417650688
0x0000000000000000, 0x0000000000000140, 0x0000000000000000, // for k = 1606938044258990275541962092341162602522202993782792835301376
0x0000000000000000, 0x0000000000000280, 0x0000000000000000, // for k = 3213876088517980551083924184682325205044405987565585670602752
0x0000000000000000, 0x0000000000000500, 0x0000000000000000, // for k = 6427752177035961102167848369364650410088811975131171341205504
0x0000000000000000, 0x0000000000000a00, 0x0000000000000000, // for k = 12855504354071922204335696738729300820177623950262342682411008
0x0000000000000000, 0x0000000000001400, 0x0000000000000000, // for k = 25711008708143844408671393477458601640355247900524685364822016
0x0000000000000000, 0x0000000000002800, 0x0000000000000000, // for k = 51422017416287688817342786954917203280710495801049370729644032
0x0000000000000000, 0x0000000000005000, 0x0000000000000000, // for k = 102844034832575377634685573909834406561420991602098741459288064
0x0000000000000000, 0x000000000000a000, 0x0000000000000000, // for k = 205688069665150755269371147819668813122841983204197482918576128
0x0000000000000000, 0x0000000000014000, 0x0000000000000000, // for k = 411376139330301510538742295639337626245683966408394965837152256
0x0000000000000000, 0x0000000000028000, 0x0000000000000000, // for k = 822752278660603021077484591278675252491367932816789931674304512
0x0000000000000000, 0x0000000000050000, 0x0000000000000000, // for k = 1645504557321206042154969182557350504982735865633579863348609024
0x0000000000000000, 0x00000000000a0000, 0x0000000000000000, // for k = 3291009114642412084309938365114701009965471731267159726697218048
0x0000000000000000, 0x0000000000140000, 0x0000000000000000, // for k = 6582018229284824168619876730229402019930943462534319453394436096
0x0000000000000000, 0x0000000000280000, 0x0000000000000000, // for k = 13164036458569648337239753460458804039861886925068638906788872192
0x0000000000000000, 0x0000000000500000, 0x0000000000000000, // for k = 26328072917139296674479506920917608079723773850137277813577744384
0x0000000000000000, 0x0000000000a00000, 0x0000000000000000, // for k = 52656145834278593348959013841835216159447547700274555627155488768
0x0000000000000000, 0x0000000001400000, 0x0000000000000000, // for k = 105312291668557186697918027683670432318895095400549111254310977536
0x0000000000000000, 0x0000000002800000, 0x0000000000000000, // for k = 210624583337114373395836055367340864637790190801098222508621955072
0x0000000000000000, 0x0000000005000000, 0x0000000000000000, // for k = 421249166674228746791672110734681729275580381602196445017243910144
0x0000000000000000, 0x000000000a000000, 0x0000000000000000, // for k = 842498333348457493583344221469363458551160763204392890034487820288
0x0000000000000000, 0x0000000014000000, 0x0000000000000000, // for k = 1684996666696914987166688442938726917102321526408785780068975640576
0x0000000000000000, 0x0000000028000000, 0x0000000000000000, // for k = 3369993333393829974333376885877453834204643052817571560137951281152
0x0000000000000000, 0x0000000050000000, 0x0000000000000000, // for k = 6739986666787659948666753771754907668409286105635143120275902562304
0x0000000000000000, 0x00000000a0000000, 0x0000000000000000, // for k = 13479973333575319897333507543509815336818572211270286240551805124608
0x0000000000000000, 0x0000000140000000, 0x0000000000000000, // for k = 26959946667150639794667015087019630673637144422540572481103610249216
0x0000000000000000, 0x0000000280000000, 0x0000000000000000, // for k = 53919893334301279589334030174039261347274288845081144962207220498432
0x0000000000000000, 0x0000000500000000, 0x0000000000000000, // for k = 107839786668602559178668060348078522694548577690162289924414440996864
0x0000000000000000, 0x0000000a00000000, 0x0000000000000000, // for k = 215679573337205118357336120696157045389097155380324579848828881993728
0x0000000000000000, 0x0000001400000000, 0x0000000000000000, // for k = 431359146674410236714672241392314090778194310760649159697657763987456
0x0000000000000000, 0x0000002800000000, 0x0000000000000000, // for k = 862718293348820473429344482784628181556388621521298319395315527974912
0x0000000000000000, 0x0000005000000000, 0x0000000000000000, // for k = 1725436586697640946858688965569256363112777243042596638790631055949824
0x0000000000000000, 0x000000a000000000, 0x0000000000000000, // for k = 3450873173395281893717377931138512726225554486085193277581262111899648
0x0000000000000000, 0x0000014000000000, 0x0000000000000000, // for k = 6901746346790563787434755862277025452451108972170386555162524223799296
0x0000000000000000, 0x0000028000000000, 0x0000000000000000, // for k = 13803492693581127574869511724554050904902217944340773110325048447598592
0x0000000000000000, 0x0000050000000000, 0x0000000000000000, // for k = 27606985387162255149739023449108101809804435888681546220650096895197184
0x0000000000000000, 0x00000a0000000000, 0x0000000000000000, // for k = 55213970774324510299478046898216203619608871777363092441300193790394368
0x0000000000000000, 0x0000140000000000, 0x0000000000000000, // for k = 110427941548649020598956093796432407239217743554726184882600387580788736
0x0000000000000000, 0x0000280000000000, 0x0000000000000000, // for k = 220855883097298041197912187592864814478435487109452369765200775161577472
0x0000000000000000, 0x0000500000000000, 0x0000000000000000, // for k = 441711766194596082395824375185729628956870974218904739530401550323154944
0x0000000000000000, 0x0000a00000000000, 0x0000000000000000, // for k = 883423532389192164791648750371459257913741948437809479060803100646309888
0x0000000000000000, 0x0001400000000000, 0x0000000000000000, // for k = 1766847064778384329583297500742918515827483896875618958121606201292619776
0x0000000000000000, 0x0002800000000000, 0x0000000000000000, // for k = 3533694129556768659166595001485837031654967793751237916243212402585239552
0x0000000000000000, 0x0005000000000000, 0x0000000000000000, // for k = 7067388259113537318333190002971674063309935587502475832486424805170479104
0x0000000000000000, 0x000a000000000000, 0x0000000000000000, // for k = 14134776518227074636666380005943348126619871175004951664972849610340958208
0x0000000000000000, 0x0014000000000000, 0x0000000000000000, // for k = 28269553036454149273332760011886696253239742350009903329945699220681916416
0x0000000000000000, 0x0028000000000000, 0x0000000000000000, // for k = 56539106072908298546665520023773392506479484700019806659891398441363832832
0x0000000000000000, 0x0050000000000000, 0x0000000000000000, // for k = 113078212145816597093331040047546785012958969400039613319782796882727665664
0x0000000000000000, 0x00a0000000000000, 0x0000000000000000, // for k = 226156424291633194186662080095093570025917938800079226639565593765455331328
0x0000000000000000, 0x0140000000000000, 0x0000000000000000, // for k = 452312848583266388373324160190187140051835877600158453279131187530910662656
0x0000000000000000, 0x0280000000000000, 0x0000000000000000, // for k = 904625697166532776746648320380374280103671755200316906558262375061821325312
0x0000000000000000, 0x0500000000000000, 0x0000000000000000, // for k = 1809251394333065553493296640760748560207343510400633813116524750123642650624
0x0000000000000000, 0x0a00000000000000, 0x0000000000000000, // for k = 3618502788666131106986593281521497120414687020801267626233049500247285301248
0x0000000000000000, 0x1400000000000000, 0x0000000000000000, // for k = 7237005577332262213973186563042994240829374041602535252466099000494570602496
0x0000000000000000, 0x2800000000000000, 0x0000000000000000, // for k = 14474011154664524427946373126085988481658748083205070504932198000989141204992
0x0000000000000000, 0x5000000000000000, 0x0000000000000000, // for k = 28948022309329048855892746252171976963317496166410141009864396001978282409984
0x0000000000000000, 0xa000000000000000, 0x0000000000000000, // for k = 57896044618658097711785492504343953926634992332820282019728792003956564819968
};

// clamp = 0x0ffffffc0ffffffc_0ffffffc0fffffff
const static uint64_t clamp_lo = 0x0ffffffc0fffffff;
const static uint64_t clamp_hi = 0x0ffffffc0ffffffc;
// const static struct my_uint128_t clamp = {
//     .lo = clamp_lo,
//     .hi = clamp_hi
// };

// p = 0x3_ffffffffffffffff_fffffffffffffffb
const uint64_t p_lo =   0xfffffffffffffffb;
const uint64_t p_mid =  0xffffffffffffffff;
const uint64_t p_hi =   0x3;
const struct my_uint192_t p = {
    .lo = p_lo,
    .mid = p_mid,
    .hi = p_hi
};

__attribute__((always_inline)) void add_my_uint128(struct my_uint128_t *a, struct my_uint128_t *b, struct my_uint128_t *result) {
    struct my_uint128_t res = {
        .lo = a->lo + b->lo,
        .hi = a->hi + b->hi + (a->lo + b->lo < a->lo)
    };
    *result = res;
}

__attribute__((always_inline)) void mul_uint64(uint64_t a, uint64_t b, struct my_uint128_t *result) {

    uint64_t a_lo = a & 0xffffffff;
    uint64_t a_hi = a >> 32;
    uint64_t b_lo = b & 0xffffffff;
    uint64_t b_hi = b >> 32;

    uint64_t lo = a_lo * b_lo;
    uint64_t hi = ((a_hi * b_lo) + (a_lo * b_hi)) << 32;

    result->lo = lo;
    result->hi = hi;
}

__attribute__((always_inline)) void mul_my_uint128(struct my_uint128_t *a, struct my_uint128_t *b, struct my_uint128_t *result) {
    
    struct my_uint128_t res = {0, 0};
    mul_uint64(a->lo, b->lo, &res);

    uint64_t first_hi = a->hi * b->lo;
    uint64_t second_hi = a->lo * b->hi;

    // We can skip a->hi * b->hi since it would be multiplied by 2^128 i.e. 0

    res.hi += first_hi;
    res.hi += second_hi;
}

__attribute__((always_inline)) void mod_my_uint128(struct my_uint128_t *a, struct my_uint192_t *p, struct my_uint128_t *result) {

    struct my_uint128_t res = {0, 0};

    

    *result = res;
}

__attribute__((always_inline)) clamp(struct my_uint128_t *x) {
    x->lo &= clamp_lo;
    x->hi &= clamp_hi;
}

__attribute__((always_inline)) int validate_tag(struct decryption_bundle_t decryption_bundle) {

    uint8_t byte;
    uint64_t qword;

    // r = int.from_bytes(key[:16], "little")
    // r = clamp(r)
    struct my_uint128_t r = {0, 0};
    for (int i=0; i<16; i++) { // TODO: correct endianess?
        SAVE_BPF_PROBE_READ_KERNEL(&byte, sizeof(byte), decryption_bundle.key + i);
        r.lo |= (uint64_t)byte << (i * 8);
    }
    for (int i=0; i<16; i++) {
        SAVE_BPF_PROBE_READ_KERNEL(&byte, sizeof(byte), decryption_bundle.tag + i + 16);
        r.hi |= (uint64_t)byte << (i * 8);        
    }
    clamp(&r);

    // s = int.from_bytes(key[16:], "little")
    struct my_uint128_t s = {0, 0};
    for (int i=0; i<16; i++) {
        SAVE_BPF_PROBE_READ_KERNEL(&byte, sizeof(byte), decryption_bundle.key + i + 16);
        s.lo |= (uint64_t)byte << (i * 8);
    }
    for (int i=0; i<16; i++) {
        SAVE_BPF_PROBE_READ_KERNEL(&byte, sizeof(byte), decryption_bundle.tag + i);
        s.hi |= (uint64_t)byte << (i * 8);        
    }

    // a = 0
    struct my_uint128_t a = {0, 0};

    // p = (1 << 130) - 5
    // p is static

    uint32_t additional_data_padding =  decryption_bundle.additional_data_size % 16 == 0 ?
                                        0 : 16 - (decryption_bundle.additional_data_size % 16);

    uint32_t payload_padding =  decryption_bundle.decyption_size % 16 == 0 ?
                                0 : 16 - (decryption_bundle.decyption_size % 16);

    uint32_t total_length = decryption_bundle.additional_data_size + additional_data_padding +
                            decryption_bundle.decyption_size + payload_padding +
                            8 + 8; // 8 bytes for additional_data_size and decryption_size as uint64_t each


    // Write data into the linearized padded map
    uint32_t ctr = 0;

    uint32_t limit_add_data = decryption_bundle.additional_data_size;
    for (int i=0; i<MAX_ADDITIONAL_DATA_SIZE; i+=8) {
        if (i >= limit_add_data) {
            // TODO: potentially do semi read with padding
            break;
        }
        bpf_probe_read_kernel(&qword, sizeof(qword), decryption_bundle.additional_data + i);
        bpf_map_update_elem(&linearized_padded_data, &ctr, &qword, BPF_ANY);
        ctr++;
    }
    // for (int i=0; i<additional_data_padding; i++) { // Implicitly done since map has type uint64_t
    //     byte = 0;
    //     bpf_map_update_elem(&linearized_padded_data, &ctr, &byte, BPF_ANY);
    //     ctr++;
    // }
    uint32_t limit_payload = decryption_bundle.decyption_size;
    for (int i=0; i<MAX_PAYLOAD_SIZE/16; i+=8) {
        REPEAT_16({
        if (i >= limit_payload) {
            // TODO: potentially do semi read with padding
            break;
        }
        bpf_probe_read_kernel(&qword, sizeof(qword), decryption_bundle.payload + i++);
        bpf_map_update_elem(&linearized_padded_data, &ctr, &qword, BPF_ANY);
        ctr++;
        });
    }
    // for (int i=0; i<payload_padding; i++) { // Implicitly done since map has type uint64_t
    //     byte = 0;
    //     bpf_map_update_elem(&linearized_padded_data, &ctr, &byte, BPF_ANY);
    //     ctr++;
    // }
    for (int i=0; i<8; i++) {
        qword = (decryption_bundle.additional_data_size >> (8 * i)) & 0xff;
        bpf_map_update_elem(&linearized_padded_data, &ctr, &qword, BPF_ANY);
        ctr++;
    }
    for (int i=0; i<8; i++) {
        qword = (decryption_bundle.decyption_size >> (8 * i)) & 0xff;
        bpf_map_update_elem(&linearized_padded_data, &ctr, &qword, BPF_ANY);
        ctr++;
    }
    

    uint32_t iterations = (total_length / 16) + (total_length % 16 == 0 ? 0 : 1);

    // TODO: do with max iterations
    //*
    for (uint32_t i=0; i<100; i++) {

        struct my_uint128_t block = {0, 0};
        
        // n = int.from_bytes(data[(i - 1) * 16:i * 16] + b"\x01", "little")
        // TODO: maybe somehow write as bytes to map and read as uint64_t directly?
        // for (int j=0; j<16; j++) {
        //     int32_t byte_index = i*16+j;

        //     uint8_t* value = bpf_map_lookup_elem(&linearized_padded_data, &byte_index);
        //     if (value == NULL) {
        //         return 1;
        //     }
        //     byte = *value;

        //     uint8_t hi_lower = block.hi && 0xff;
        //     block.hi = (block.hi >> 8) | (byte << 56);
        //     block.lo = (block.lo >> 8) | (hi_lower << 56);
        // }
        // uint8_t hi_lower = block.hi && 0xff;
        // block.hi = (block.hi >> 8) | (0x01 << 56);
        // block.lo = (block.lo >> 8) | (hi_lower << 56);

        uint32_t index = i;
        uint64_t *hi = bpf_map_lookup_elem(&linearized_padded_data, &index);
        if (hi == NULL) {
            return 1;
        }
        index = i + 1;
        uint64_t *lo = bpf_map_lookup_elem(&linearized_padded_data, &index);
        if (lo == NULL) {
            return 1;
        }

        block.hi = *hi;
        block.lo = *lo;

        // a += n
        struct my_uint128_t a_old = a;
        add_my_uint128(&a_old, &block, &a);

        // a = (r * a) % p
        // TODO
        a_old = a;
        mul_my_uint128(&a_old, &r, &a);
        a_old = a;
        mod_my_uint128(&a_old, &p, &a); // https://electronics.stackexchange.com/questions/608840/verilog-modulus-operator-for-non-power-of-two-synthetizable/608854#608854

    }
    //*/

    // a += s
    struct my_uint128_t a_old = a;
    add_my_uint128(&a_old, &s, &a);

    // Now the 128 least significant bits of a should be equal to the tag
    // TODO: check this
        
    return 0;
}
