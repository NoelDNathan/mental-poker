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
    uint256 constant alphax  = 9152647065507872436081980583259775161116185537155821928381609317288203431234;
    uint256 constant alphay  = 7921978052549367086607984922735946076975263200180516913132590725745427192408;
    uint256 constant betax1  = 14859874846920962722357200142132714692896942647397346754266446518291435440797;
    uint256 constant betax2  = 32689996325286202652508777513010515266420480197797185575162127639289405388;
    uint256 constant betay1  = 8525554062963175769472044842034281951754553607735911182844301239810794783299;
    uint256 constant betay2  = 13612756381466074184458089498557775985423839857824535826841605092490077717595;
    uint256 constant gammax1 = 11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 constant gammax2 = 10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 constant gammay1 = 4082367875863433681332203403145435568316851327593401208105741076214120093531;
    uint256 constant gammay2 = 8495653923123431417604973247489272438418190587263600148770280649306958101930;
    uint256 constant deltax1 = 1930654073389854382762134252751919926673977228261871547177554833404806762782;
    uint256 constant deltax2 = 1363125925350267831246010096968567031084610885219242400491408930486816429937;
    uint256 constant deltay1 = 17703725371432757692388207155915063574934065688808108653644954262669916441469;
    uint256 constant deltay2 = 10362826487582289048284935797038412135005468349739615005599909078116768344995;

    
    uint256 constant IC0x = 11635235497439630166222587070273046168227435333935007859881891871365628875061;
    uint256 constant IC0y = 15057256549825969853297898069421231454952571710641813412537167831176243113105;
    
    uint256 constant IC1x = 4475126111708466619344393516801464349549171876320099807695933449265990817369;
    uint256 constant IC1y = 1743485872405338632339112120730444631856546731936440139221664648155438926544;
    
    uint256 constant IC2x = 8045006562341979179805175711955891440592335479669661164817948911633189538666;
    uint256 constant IC2y = 20480891914173570198051906300663171132109516031606773072962447138527692912538;
    
    uint256 constant IC3x = 4450173135375822226851721770168319517183964802596453522710332215529679325898;
    uint256 constant IC3y = 17742665487364394000160542151533993977942838445535610941468985020396862741138;
    
    uint256 constant IC4x = 5363049367822595653524341531619204264233689738177842651771969794647932814039;
    uint256 constant IC4y = 20516121914338220620742132521927842565042065718831877972610958609267898880766;
    
    uint256 constant IC5x = 3749197893873613983268001849727593909541992935325985143592608200652983060880;
    uint256 constant IC5y = 13144295122425021800976650693417850559778712607100460895954731554372073592024;
    
    uint256 constant IC6x = 19003628696142600699500375385571290974715545575925278182968577990298700359821;
    uint256 constant IC6y = 14451789265674633228177569658381302783383953684304410261931342813351227226888;
    
    uint256 constant IC7x = 7131936471815898091116687180744744235041869291714998901310556244202653739070;
    uint256 constant IC7y = 14627504756181520313102010112264412884260172593516586046093210094499833474130;
    
    uint256 constant IC8x = 16873471081657413823357531010673828597724214843890424651596141725618260688715;
    uint256 constant IC8y = 18472478810005155969374339385845513027564453657361383557708618907307840443283;
    
    uint256 constant IC9x = 8755968941108331154314270362705453400620948304500174035541273556978224934095;
    uint256 constant IC9y = 8763052663160324046818356508046284221998500002421158692647685249485483821818;
    
    uint256 constant IC10x = 3169046391783306411973280143036835084945732447966770037061222940156527437853;
    uint256 constant IC10y = 12423076194172432711391906134183607029929791735789302423557113323753939988814;
    
    uint256 constant IC11x = 3856067216004275229724551870254517886894511429935111568940408530557168084552;
    uint256 constant IC11y = 17058626641599724297030119643241075814312721351373191719334258733621551015821;
    
    uint256 constant IC12x = 8960979580270798794395309073698598186565239510561887926899974231090121226095;
    uint256 constant IC12y = 9156882423072074237489376933956587370916577745256044457998300106506057793950;
    
    uint256 constant IC13x = 5899286210304500185933833543130494765008060611394187561733438077175198315409;
    uint256 constant IC13y = 18798908029647522683435386920804600582920909274677662430387336957018580976033;
    
    uint256 constant IC14x = 10582109756111326232359550225977159690536479149244981103652853131739824151314;
    uint256 constant IC14y = 9673230302183023391126978683134682570606616832092839086358787697455930366954;
    
    uint256 constant IC15x = 9357102689252181920793607203978755549435888935012651528136930450193583411677;
    uint256 constant IC15y = 11609062877920163586762472928761505488743962590917360043379288660044691960604;
    
    uint256 constant IC16x = 21268274610172874893571332705689821846978555139482347986300312730547178541656;
    uint256 constant IC16y = 17847633915764681586173155119499312967203048136167423379862942923680536925661;
    
    uint256 constant IC17x = 8821419168954334936428337120294136625455326616308540758373910820638737652676;
    uint256 constant IC17y = 15858183674823916413101876385680845319602938196254949081238862074011368746414;
    
    uint256 constant IC18x = 3024889183753695777544113327551429967306198830627676822490858899311714285562;
    uint256 constant IC18y = 12229884130141876242104552212143564173393176245602354706334295952750837163780;
    
    uint256 constant IC19x = 5563477103781250530703122843540325206377996677673769532327189206087510668825;
    uint256 constant IC19y = 19297703292663317700914551063800562009819811267794032990089903382745922936687;
    
    uint256 constant IC20x = 11517263349411152073949562964500033692147424406961850772867810705374926737783;
    uint256 constant IC20y = 10966222635766641069753311328763585890427726838577566329847275975681702295055;
    
 
    // Memory data
    uint16 constant pVk = 0;
    uint16 constant pPairing = 128;

    uint16 constant pLastMem = 896;

    function verifyProof(uint[2] calldata _pA, uint[2][2] calldata _pB, uint[2] calldata _pC, uint[20] calldata _pubSignals) public view returns (bool) {
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
            

            // Validate all evaluations
            let isValid := checkPairing(_pA, _pB, _pC, _pubSignals, pMem)

            mstore(0, isValid)
             return(0, 0x20)
         }
     }
 }
