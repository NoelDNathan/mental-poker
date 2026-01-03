// SPDX-License-Identifier: GPL-3.0
/*
    Copyright 2021 0KIMS association.

    This file is generated with [snarkJS](https://github.com/iden3/snarkjs).

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/

pragma solidity >=0.7.0 <0.9.0;

contract Groth16Verifier {
    // Scalar field size
    uint256 constant r    = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    // Base field size
    uint256 constant q   = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    // Verification Key data
    uint256 constant alphax  = 1262043093156821418990611511905297986789457705784177989822914950301532748776;
    uint256 constant alphay  = 9232420492285245000572362180113079627269075234839104988914501196780669822876;
    uint256 constant betax1  = 14711091984570209537520328103907097929807704308474886895577409410788596508561;
    uint256 constant betax2  = 13884977405483176276510260194893207787801727962185496312893286754787473171631;
    uint256 constant betay1  = 19806479395019495797443994054634467635262137374033328628424861261410885198409;
    uint256 constant betay2  = 6150581141560580053087591259384011176923199948220576901425135762753588557941;
    uint256 constant gammax1 = 11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 constant gammax2 = 10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 constant gammay1 = 4082367875863433681332203403145435568316851327593401208105741076214120093531;
    uint256 constant gammay2 = 8495653923123431417604973247489272438418190587263600148770280649306958101930;
    uint256 constant deltax1 = 175499652012472024400476927966573215638040429937647449357401585289285248355;
    uint256 constant deltax2 = 4697300499445747597028040017637093700911787123405484986107353733304594572932;
    uint256 constant deltay1 = 14232293726191297162891884818712811205585136153973887997713968558037673944712;
    uint256 constant deltay2 = 16268314207476497997824828174946537353204380871575721291619505244608970001281;

    
    uint256 constant IC0x = 9684340870239513191952886238178389576465613409226633959654670780114910726424;
    uint256 constant IC0y = 19006249319185703913780552386134088827853192460857909586636896083081353960915;
    
    uint256 constant IC1x = 18144591316648520635771373314388377622682618003498044591749403827758313813131;
    uint256 constant IC1y = 14510670871403546108066050177825617339341498461500638048830015787556885021630;
    
    uint256 constant IC2x = 7473863635837537176747137351601843693452139325594294049001438006171737057407;
    uint256 constant IC2y = 8835960805383749494715433485715010921242987971393529253639801605733592092779;
    
    uint256 constant IC3x = 2341856385005361948651879456015488050992990872985503292923001923613633512190;
    uint256 constant IC3y = 8198088737359884636253714552058788487097468485161585432473519808658475630943;
    
    uint256 constant IC4x = 11523942696316723998548886183378770920250994018565091831190340761033166314537;
    uint256 constant IC4y = 1143467084733388265093881996943727112594851281399196113751047397714669080047;
    
    uint256 constant IC5x = 19594091124855753746049443928544077520508645575016888358655218095973376352778;
    uint256 constant IC5y = 5045886163067430426154318815774090719848841696720542933796108373173237645945;
    
    uint256 constant IC6x = 12007544589949096122157451782283182959174240023421728119851933353365796106812;
    uint256 constant IC6y = 15153213246122997429359004488032330277065622427884778020172038858832761494203;
    
    uint256 constant IC7x = 21842800530959872735585325824049264366888105083907869549771806923750516978805;
    uint256 constant IC7y = 5521093324833789136980742922432486682762240155703936330035530713409087039704;
    
    uint256 constant IC8x = 19503111836555512917065559528537591523101918833030327627721895604390440895159;
    uint256 constant IC8y = 4830098625562062173132823956469119217819538905897315237426002940654341500772;
    
    uint256 constant IC9x = 8294477241752582224970787076673388726606842856238395175439572697812104986490;
    uint256 constant IC9y = 7380218589118912358400085878745593144528459227273535834043440671585145125999;
    
    uint256 constant IC10x = 1420283689988818021620638837809153878374091236947936333089880240038728097255;
    uint256 constant IC10y = 9493129250146141085715224283777525655561049969792042847079096518469467960348;
    
    uint256 constant IC11x = 5496612983757571407151546003625435299509031846644981861010291840755926811984;
    uint256 constant IC11y = 21145637035367590534922039006438231297344445382762569109325990035506448463110;
    
    uint256 constant IC12x = 2448836504841065090783168777425862901450321693116473831607720797688726461948;
    uint256 constant IC12y = 11576213373536237590337171762739083551497894107879679645626352334709247345202;
    
    uint256 constant IC13x = 8668734993813158561991996216385361329840366899588691100093396910870744575351;
    uint256 constant IC13y = 13808975483979414509104170475854982586833790759230053776447425131155886383065;
    
    uint256 constant IC14x = 8686453096787448592227401635913240860793587050805677665071269417868481298130;
    uint256 constant IC14y = 16503505756009739785426654364074699751023284051975557160959599037900298050647;
    
    uint256 constant IC15x = 795143136448694428025096681064616513195332757593444712657255081263017411197;
    uint256 constant IC15y = 7046488937045833824370582436603921016036443702090472202631068895895204467822;
    
    uint256 constant IC16x = 11807032949285845802751384200741106981342040953064739545619101699470484979992;
    uint256 constant IC16y = 2811772524270258913861545276589391869507112870056250554442806333264543983344;
    
    uint256 constant IC17x = 13466869828610004339299157600111525964276216820974874975494223839972356367000;
    uint256 constant IC17y = 18005573688702156624703023959673761019636367764340239698592153954830714474825;
    
    uint256 constant IC18x = 20997849009854371523533626096851376418972025618526993011578164051392611654851;
    uint256 constant IC18y = 19615676705247382915089466980763761195447698973192342190418621970415327061889;
    
    uint256 constant IC19x = 21002867940241815366333530768956505975909876647830593201719259250242700846482;
    uint256 constant IC19y = 5732146028623936926249233394926116715385755794711523419144361405289095283555;
    
    uint256 constant IC20x = 7273922061761866971755229367890688885842761337718508992082226736428529355923;
    uint256 constant IC20y = 7607542849303860006602552474318031539675376065834091376834538990053462069805;
    
    uint256 constant IC21x = 10659262406817690022848263792667428844011836375991803084452163174499830719520;
    uint256 constant IC21y = 18038854555795935619301969236283237297525697069061895999861660143936926827900;
    
    uint256 constant IC22x = 13772430464693485340093666581253936683237482173503565629431130520066204256358;
    uint256 constant IC22y = 16250532362913150781211523927311542430928570350046683742745223036477228135041;
    
    uint256 constant IC23x = 13124237653267990905216137969205834805366684295443200002063220860079160260052;
    uint256 constant IC23y = 11190366595293908696077886043181395033961326918771418989312084517010502249085;
    
    uint256 constant IC24x = 12715583119449915374446279057448462357938311530810177956144519259095860413212;
    uint256 constant IC24y = 21651502603983973679096012987289199849546932112689775123814064513143545203799;
    
    uint256 constant IC25x = 21144577382462431942078461054807321746993607333925240788545360552513561480017;
    uint256 constant IC25y = 20680914496535960177343367594143543668046168010525951003535133471059035468427;
    
    uint256 constant IC26x = 15701892261497871669580867516807260608004117112548256677710342568854074992309;
    uint256 constant IC26y = 7064702615297134464746896935950315188406342949708091464926749397359610700415;
    
    uint256 constant IC27x = 21498707640731288218570112941245214480567897941570814028559370432219129023396;
    uint256 constant IC27y = 5913782248949978787839245466623890012021483638023472090030481720373317235801;
    
    uint256 constant IC28x = 7047357736447448406971589479885818302471731010643310871543822715631611855201;
    uint256 constant IC28y = 347319620628635935641252110748817818942158499461828388417138903103422638074;
    
    uint256 constant IC29x = 8134609487726176781563125315751501468612821291167472006681225370405455914815;
    uint256 constant IC29y = 621444766207765625768806602019506104252870843772253050843453852378818713820;
    
    uint256 constant IC30x = 6622673964928361373750223240960314380395660360609241264582704118256177957779;
    uint256 constant IC30y = 932251902050161374214449710673660263354430078591282741907486645091247620918;
    
    uint256 constant IC31x = 18300236858091244247137497378334966600567490613456498474017305576015918949699;
    uint256 constant IC31y = 8156712861084747182212816683754643329995492270722888271941780093764869802925;
    
    uint256 constant IC32x = 11066421117811592913235078153956361382042337500452471645635607162612162396955;
    uint256 constant IC32y = 13051892626583210692035203722097279581019051694391678046023945130293528126743;
    
    uint256 constant IC33x = 14775759312440101748311953205334487569950901857416139406586723729000780673570;
    uint256 constant IC33y = 10189038046411167661397573423300006628528987033519609997940598423513588123186;
    
    uint256 constant IC34x = 153651292224986035282636515410935376015094251985381369451004138868493522532;
    uint256 constant IC34y = 21224820300748958681179934950885201814777093027234808342219009048194717418247;
    
    uint256 constant IC35x = 11350420874522919624772606539299692141983098939706971131482220359407927653447;
    uint256 constant IC35y = 5351893641438418486085783094175338196429018809719552648643446225348883513171;
    
    uint256 constant IC36x = 21375504181548069664982040205432997601062470307252719509218442335640262113806;
    uint256 constant IC36y = 12582298016206434920258849901571519944809464315182315682666094787871044505051;
    
    uint256 constant IC37x = 11800766743633670343325558424423366750233152374823787180043809711438884033961;
    uint256 constant IC37y = 10275275354841574097283089589540522375518626351300334901414665387095457229237;
    
    uint256 constant IC38x = 2009992987490969725496852723770915504607503535851035149835227917123327799721;
    uint256 constant IC38y = 17057018306860003243113921568571407715276527216930077137512778683501784068569;
    
    uint256 constant IC39x = 18844419719803603366526498922588364490279260913634084085955388034228363128302;
    uint256 constant IC39y = 12936954211302678860065149661188292758469172977164903127560409969108253322782;
    
    uint256 constant IC40x = 9028077608704310315670452810171975495752030526813346826714496350287381680932;
    uint256 constant IC40y = 15939228347370347471667068926622827279991449065978667652892658799981247309443;
    
    uint256 constant IC41x = 18288161592678114154461867796231918223484170557311889184370466575391476460664;
    uint256 constant IC41y = 15921217529594992267124709703043947435514398158644368408972155970481554644734;
    
    uint256 constant IC42x = 20222659055801123433008023696083635740324742859017885844963087105196757080766;
    uint256 constant IC42y = 18736485674780966817420844896708467232952794367606704751982430247927489867344;
    
    uint256 constant IC43x = 11910475938427812554235602966528538452086392394358298677965178706978276052759;
    uint256 constant IC43y = 9529426198274665870489348596754981160497333572105958744670646347338914960703;
    
    uint256 constant IC44x = 17549695394985179058963110348906504790694648432893145564815541763441701179819;
    uint256 constant IC44y = 5747274285370822092563185273859558462973864420728006398259029506144832170613;
    
    uint256 constant IC45x = 16992247597382401028854484070238179991984054697499033952948722485931830921411;
    uint256 constant IC45y = 14168051040380292167585129506593563229382729511447527890088198466050943109726;
    
    uint256 constant IC46x = 12732165762450456486070432617047734258092416120679670866675189262053101491880;
    uint256 constant IC46y = 4430359339037649577554601091703103782980699283970927572164906503457252211930;
    
    uint256 constant IC47x = 7714696289336744134921270913978855444492218271848146391675123872693104165275;
    uint256 constant IC47y = 10575912137718926889365660914252099945257215235323750636237657750751269081515;
    
    uint256 constant IC48x = 12492257634337988612863701824933065238453157422605660034263892980391941884780;
    uint256 constant IC48y = 3628336296228300569488618753181141146699930298473025583125863473144884808402;
    
    uint256 constant IC49x = 14848367750596637246584071113064161034685642760975583787458711743344319018760;
    uint256 constant IC49y = 12978323225085488740801879509545930651176436719535257830743787157942843183742;
    
    uint256 constant IC50x = 8516504693888228693148089459654000762073659020241894927465050128012018624215;
    uint256 constant IC50y = 5904929318658164205227738631065611260100573559454911028542981094040519695172;
    
    uint256 constant IC51x = 3939679156074456044960834269455860102836727480584924366346141415987793216557;
    uint256 constant IC51y = 20907223073773800657016535052321832577531475293304502734062167104573764461814;
    
    uint256 constant IC52x = 18878579593212237878052795341547908707975902777923495063552995407383657786491;
    uint256 constant IC52y = 4443120738165794086436236345192737881785908315467838190428704418468583964456;
    
    uint256 constant IC53x = 12687677484269566644504344706008729471233454122803228716986034716108934604680;
    uint256 constant IC53y = 20463849216800931058653725997574331469643901565932177575103902418709910838004;
    
    uint256 constant IC54x = 7796760753768456948947355817891963302710065017228433094925106827237620753114;
    uint256 constant IC54y = 3989520905164690931149534725946572111510026864424384738733839254024368003604;
    
    uint256 constant IC55x = 15717518732561815765118497252234682327788818182442138570158607701359411527673;
    uint256 constant IC55y = 7056351227182100252430484558906790563028532207263961489475228311796596774443;
    
    uint256 constant IC56x = 14554724235018261631205123678942443493336052985540562076133573757485007742610;
    uint256 constant IC56y = 4011920952737907457326983849627988193451641964997973142721027050162968421963;
    
    uint256 constant IC57x = 11608301020516025896786494737149114503040712984776203259943809079606566847096;
    uint256 constant IC57y = 2351979164624904237077773638573867510290924979578668951262617132587831720135;
    
    uint256 constant IC58x = 14902554733982971059205831322253456616437391531594777774652099037264530961337;
    uint256 constant IC58y = 15897001640812534876507017210463912878355284073220025751844322496140954584772;
    
    uint256 constant IC59x = 10399455126139086747492680066973851017042327079583760449643481402876751426970;
    uint256 constant IC59y = 18739222090083445591879112274081800459812333954210108289960106483600474609827;
    
    uint256 constant IC60x = 12351997520227211619951699704247811673342819077776394980036328756940875953;
    uint256 constant IC60y = 11428829957138819133193929830517405066952233148022134402479167712544475272967;
    
 
    // Memory data
    uint16 constant pVk = 0;
    uint16 constant pPairing = 128;

    uint16 constant pLastMem = 896;

    function verifyProof(uint[2] calldata _pA, uint[2][2] calldata _pB, uint[2] calldata _pC, uint[60] calldata _pubSignals) public view returns (bool) {
        assembly {
            function checkField(v) {
                if iszero(lt(v, r)) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }
            
            // G1 function to multiply a G1 value(x,y) to value in an address
            function g1_mulAccC(pR, x, y, s) {
                let success
                let mIn := mload(0x40)
                mstore(mIn, x)
                mstore(add(mIn, 32), y)
                mstore(add(mIn, 64), s)

                success := staticcall(sub(gas(), 2000), 7, mIn, 96, mIn, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }

                mstore(add(mIn, 64), mload(pR))
                mstore(add(mIn, 96), mload(add(pR, 32)))

                success := staticcall(sub(gas(), 2000), 6, mIn, 128, pR, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }

            function checkPairing(pA, pB, pC, pubSignals, pMem) -> isOk {
                let _pPairing := add(pMem, pPairing)
                let _pVk := add(pMem, pVk)

                mstore(_pVk, IC0x)
                mstore(add(_pVk, 32), IC0y)

                // Compute the linear combination vk_x
                
                g1_mulAccC(_pVk, IC1x, IC1y, calldataload(add(pubSignals, 0)))
                
                g1_mulAccC(_pVk, IC2x, IC2y, calldataload(add(pubSignals, 32)))
                
                g1_mulAccC(_pVk, IC3x, IC3y, calldataload(add(pubSignals, 64)))
                
                g1_mulAccC(_pVk, IC4x, IC4y, calldataload(add(pubSignals, 96)))
                
                g1_mulAccC(_pVk, IC5x, IC5y, calldataload(add(pubSignals, 128)))
                
                g1_mulAccC(_pVk, IC6x, IC6y, calldataload(add(pubSignals, 160)))
                
                g1_mulAccC(_pVk, IC7x, IC7y, calldataload(add(pubSignals, 192)))
                
                g1_mulAccC(_pVk, IC8x, IC8y, calldataload(add(pubSignals, 224)))
                
                g1_mulAccC(_pVk, IC9x, IC9y, calldataload(add(pubSignals, 256)))
                
                g1_mulAccC(_pVk, IC10x, IC10y, calldataload(add(pubSignals, 288)))
                
                g1_mulAccC(_pVk, IC11x, IC11y, calldataload(add(pubSignals, 320)))
                
                g1_mulAccC(_pVk, IC12x, IC12y, calldataload(add(pubSignals, 352)))
                
                g1_mulAccC(_pVk, IC13x, IC13y, calldataload(add(pubSignals, 384)))
                
                g1_mulAccC(_pVk, IC14x, IC14y, calldataload(add(pubSignals, 416)))
                
                g1_mulAccC(_pVk, IC15x, IC15y, calldataload(add(pubSignals, 448)))
                
                g1_mulAccC(_pVk, IC16x, IC16y, calldataload(add(pubSignals, 480)))
                
                g1_mulAccC(_pVk, IC17x, IC17y, calldataload(add(pubSignals, 512)))
                
                g1_mulAccC(_pVk, IC18x, IC18y, calldataload(add(pubSignals, 544)))
                
                g1_mulAccC(_pVk, IC19x, IC19y, calldataload(add(pubSignals, 576)))
                
                g1_mulAccC(_pVk, IC20x, IC20y, calldataload(add(pubSignals, 608)))
                
                g1_mulAccC(_pVk, IC21x, IC21y, calldataload(add(pubSignals, 640)))
                
                g1_mulAccC(_pVk, IC22x, IC22y, calldataload(add(pubSignals, 672)))
                
                g1_mulAccC(_pVk, IC23x, IC23y, calldataload(add(pubSignals, 704)))
                
                g1_mulAccC(_pVk, IC24x, IC24y, calldataload(add(pubSignals, 736)))
                
                g1_mulAccC(_pVk, IC25x, IC25y, calldataload(add(pubSignals, 768)))
                
                g1_mulAccC(_pVk, IC26x, IC26y, calldataload(add(pubSignals, 800)))
                
                g1_mulAccC(_pVk, IC27x, IC27y, calldataload(add(pubSignals, 832)))
                
                g1_mulAccC(_pVk, IC28x, IC28y, calldataload(add(pubSignals, 864)))
                
                g1_mulAccC(_pVk, IC29x, IC29y, calldataload(add(pubSignals, 896)))
                
                g1_mulAccC(_pVk, IC30x, IC30y, calldataload(add(pubSignals, 928)))
                
                g1_mulAccC(_pVk, IC31x, IC31y, calldataload(add(pubSignals, 960)))
                
                g1_mulAccC(_pVk, IC32x, IC32y, calldataload(add(pubSignals, 992)))
                
                g1_mulAccC(_pVk, IC33x, IC33y, calldataload(add(pubSignals, 1024)))
                
                g1_mulAccC(_pVk, IC34x, IC34y, calldataload(add(pubSignals, 1056)))
                
                g1_mulAccC(_pVk, IC35x, IC35y, calldataload(add(pubSignals, 1088)))
                
                g1_mulAccC(_pVk, IC36x, IC36y, calldataload(add(pubSignals, 1120)))
                
                g1_mulAccC(_pVk, IC37x, IC37y, calldataload(add(pubSignals, 1152)))
                
                g1_mulAccC(_pVk, IC38x, IC38y, calldataload(add(pubSignals, 1184)))
                
                g1_mulAccC(_pVk, IC39x, IC39y, calldataload(add(pubSignals, 1216)))
                
                g1_mulAccC(_pVk, IC40x, IC40y, calldataload(add(pubSignals, 1248)))
                
                g1_mulAccC(_pVk, IC41x, IC41y, calldataload(add(pubSignals, 1280)))
                
                g1_mulAccC(_pVk, IC42x, IC42y, calldataload(add(pubSignals, 1312)))
                
                g1_mulAccC(_pVk, IC43x, IC43y, calldataload(add(pubSignals, 1344)))
                
                g1_mulAccC(_pVk, IC44x, IC44y, calldataload(add(pubSignals, 1376)))
                
                g1_mulAccC(_pVk, IC45x, IC45y, calldataload(add(pubSignals, 1408)))
                
                g1_mulAccC(_pVk, IC46x, IC46y, calldataload(add(pubSignals, 1440)))
                
                g1_mulAccC(_pVk, IC47x, IC47y, calldataload(add(pubSignals, 1472)))
                
                g1_mulAccC(_pVk, IC48x, IC48y, calldataload(add(pubSignals, 1504)))
                
                g1_mulAccC(_pVk, IC49x, IC49y, calldataload(add(pubSignals, 1536)))
                
                g1_mulAccC(_pVk, IC50x, IC50y, calldataload(add(pubSignals, 1568)))
                
                g1_mulAccC(_pVk, IC51x, IC51y, calldataload(add(pubSignals, 1600)))
                
                g1_mulAccC(_pVk, IC52x, IC52y, calldataload(add(pubSignals, 1632)))
                
                g1_mulAccC(_pVk, IC53x, IC53y, calldataload(add(pubSignals, 1664)))
                
                g1_mulAccC(_pVk, IC54x, IC54y, calldataload(add(pubSignals, 1696)))
                
                g1_mulAccC(_pVk, IC55x, IC55y, calldataload(add(pubSignals, 1728)))
                
                g1_mulAccC(_pVk, IC56x, IC56y, calldataload(add(pubSignals, 1760)))
                
                g1_mulAccC(_pVk, IC57x, IC57y, calldataload(add(pubSignals, 1792)))
                
                g1_mulAccC(_pVk, IC58x, IC58y, calldataload(add(pubSignals, 1824)))
                
                g1_mulAccC(_pVk, IC59x, IC59y, calldataload(add(pubSignals, 1856)))
                
                g1_mulAccC(_pVk, IC60x, IC60y, calldataload(add(pubSignals, 1888)))
                

                // -A
                mstore(_pPairing, calldataload(pA))
                mstore(add(_pPairing, 32), mod(sub(q, calldataload(add(pA, 32))), q))

                // B
                mstore(add(_pPairing, 64), calldataload(pB))
                mstore(add(_pPairing, 96), calldataload(add(pB, 32)))
                mstore(add(_pPairing, 128), calldataload(add(pB, 64)))
                mstore(add(_pPairing, 160), calldataload(add(pB, 96)))

                // alpha1
                mstore(add(_pPairing, 192), alphax)
                mstore(add(_pPairing, 224), alphay)

                // beta2
                mstore(add(_pPairing, 256), betax1)
                mstore(add(_pPairing, 288), betax2)
                mstore(add(_pPairing, 320), betay1)
                mstore(add(_pPairing, 352), betay2)

                // vk_x
                mstore(add(_pPairing, 384), mload(add(pMem, pVk)))
                mstore(add(_pPairing, 416), mload(add(pMem, add(pVk, 32))))


                // gamma2
                mstore(add(_pPairing, 448), gammax1)
                mstore(add(_pPairing, 480), gammax2)
                mstore(add(_pPairing, 512), gammay1)
                mstore(add(_pPairing, 544), gammay2)

                // C
                mstore(add(_pPairing, 576), calldataload(pC))
                mstore(add(_pPairing, 608), calldataload(add(pC, 32)))

                // delta2
                mstore(add(_pPairing, 640), deltax1)
                mstore(add(_pPairing, 672), deltax2)
                mstore(add(_pPairing, 704), deltay1)
                mstore(add(_pPairing, 736), deltay2)


                let success := staticcall(sub(gas(), 2000), 8, _pPairing, 768, _pPairing, 0x20)

                isOk := and(success, mload(_pPairing))
            }

            let pMem := mload(0x40)
            mstore(0x40, add(pMem, pLastMem))

            // Validate that all evaluations ∈ F
            
            checkField(calldataload(add(_pubSignals, 0)))
            
            checkField(calldataload(add(_pubSignals, 32)))
            
            checkField(calldataload(add(_pubSignals, 64)))
            
            checkField(calldataload(add(_pubSignals, 96)))
            
            checkField(calldataload(add(_pubSignals, 128)))
            
            checkField(calldataload(add(_pubSignals, 160)))
            
            checkField(calldataload(add(_pubSignals, 192)))
            
            checkField(calldataload(add(_pubSignals, 224)))
            
            checkField(calldataload(add(_pubSignals, 256)))
            
            checkField(calldataload(add(_pubSignals, 288)))
            
            checkField(calldataload(add(_pubSignals, 320)))
            
            checkField(calldataload(add(_pubSignals, 352)))
            
            checkField(calldataload(add(_pubSignals, 384)))
            
            checkField(calldataload(add(_pubSignals, 416)))
            
            checkField(calldataload(add(_pubSignals, 448)))
            
            checkField(calldataload(add(_pubSignals, 480)))
            
            checkField(calldataload(add(_pubSignals, 512)))
            
            checkField(calldataload(add(_pubSignals, 544)))
            
            checkField(calldataload(add(_pubSignals, 576)))
            
            checkField(calldataload(add(_pubSignals, 608)))
            
            checkField(calldataload(add(_pubSignals, 640)))
            
            checkField(calldataload(add(_pubSignals, 672)))
            
            checkField(calldataload(add(_pubSignals, 704)))
            
            checkField(calldataload(add(_pubSignals, 736)))
            
            checkField(calldataload(add(_pubSignals, 768)))
            
            checkField(calldataload(add(_pubSignals, 800)))
            
            checkField(calldataload(add(_pubSignals, 832)))
            
            checkField(calldataload(add(_pubSignals, 864)))
            
            checkField(calldataload(add(_pubSignals, 896)))
            
            checkField(calldataload(add(_pubSignals, 928)))
            
            checkField(calldataload(add(_pubSignals, 960)))
            
            checkField(calldataload(add(_pubSignals, 992)))
            
            checkField(calldataload(add(_pubSignals, 1024)))
            
            checkField(calldataload(add(_pubSignals, 1056)))
            
            checkField(calldataload(add(_pubSignals, 1088)))
            
            checkField(calldataload(add(_pubSignals, 1120)))
            
            checkField(calldataload(add(_pubSignals, 1152)))
            
            checkField(calldataload(add(_pubSignals, 1184)))
            
            checkField(calldataload(add(_pubSignals, 1216)))
            
            checkField(calldataload(add(_pubSignals, 1248)))
            
            checkField(calldataload(add(_pubSignals, 1280)))
            
            checkField(calldataload(add(_pubSignals, 1312)))
            
            checkField(calldataload(add(_pubSignals, 1344)))
            
            checkField(calldataload(add(_pubSignals, 1376)))
            
            checkField(calldataload(add(_pubSignals, 1408)))
            
            checkField(calldataload(add(_pubSignals, 1440)))
            
            checkField(calldataload(add(_pubSignals, 1472)))
            
            checkField(calldataload(add(_pubSignals, 1504)))
            
            checkField(calldataload(add(_pubSignals, 1536)))
            
            checkField(calldataload(add(_pubSignals, 1568)))
            
            checkField(calldataload(add(_pubSignals, 1600)))
            
            checkField(calldataload(add(_pubSignals, 1632)))
            
            checkField(calldataload(add(_pubSignals, 1664)))
            
            checkField(calldataload(add(_pubSignals, 1696)))
            
            checkField(calldataload(add(_pubSignals, 1728)))
            
            checkField(calldataload(add(_pubSignals, 1760)))
            
            checkField(calldataload(add(_pubSignals, 1792)))
            
            checkField(calldataload(add(_pubSignals, 1824)))
            
            checkField(calldataload(add(_pubSignals, 1856)))
            
            checkField(calldataload(add(_pubSignals, 1888)))
            

            // Validate all evaluations
            let isValid := checkPairing(_pA, _pB, _pC, _pubSignals, pMem)

            mstore(0, isValid)
             return(0, 0x20)
         }
     }
 }
