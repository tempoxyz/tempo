// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.13 <0.9.0;

/// @notice Ported to Solidity 0.8 from https://github.com/chengwenxi/Ed25519 (Apache-2.0)
import { Sha512 } from "./Sha512.sol";

library Ed25519 {

    // Computes (v^(2^250-1), v^11) mod p
    function pow22501(uint256 v) private pure returns (uint256 p22501, uint256 p11) {
        p11 = mulmod(v, v, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        p22501 =
            mulmod(p11, p11, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        p22501 = mulmod(
            mulmod(
                p22501, p22501, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
            ),
            v,
            0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
        );
        p11 = mulmod(
            p22501, p11, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
        );
        p22501 = mulmod(
            mulmod(p11, p11, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed),
            p22501,
            0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
        );
        uint256 a = mulmod(
            p22501, p22501, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
        );
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        p22501 =
            mulmod(p22501, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(
            p22501, p22501, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
        );
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(p22501, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        uint256 b = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        p22501 =
            mulmod(p22501, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(
            p22501, p22501, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
        );
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(p22501, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        b = mulmod(b, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, b, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        a = mulmod(a, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
        p22501 =
            mulmod(p22501, a, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
    }

    function _unpackKey(bytes32 k) private pure returns (bool valid, uint256 kx, uint256 ky) {
        unchecked {
            uint256 ky_ =
                uint256(k) & 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff;
            uint256 kx_;
            uint256 ky2 = mulmod(
                ky_, ky_, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
            );
            uint256 u = addmod(
                ky2,
                0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec,
                0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
            );
            uint256 v = mulmod(
                ky2,
                0x52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3,
                0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
            ) + 1;
            uint256 t =
                mulmod(u, v, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
            (kx_,) = pow22501(t);
            kx_ = mulmod(
                kx_, kx_, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
            );
            kx_ = mulmod(
                u,
                mulmod(
                    mulmod(
                        kx_, kx_, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
                    ),
                    t,
                    0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
                ),
                0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
            );
            t = mulmod(
                mulmod(
                    kx_, kx_, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
                ),
                v,
                0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
            );
            if (t != u) {
                if (t != 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed - u) {
                    return (false, 0, 0);
                }
                kx_ = mulmod(
                    kx_,
                    0x2b8324804fc1df0b2b4d00993dfbd7a72f431806ad2fe478c4ee1b274a0ea0b0,
                    0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
                );
            }
            if ((kx_ & 1) != uint256(k) >> 255) {
                kx_ = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed - kx_;
            }
            return (true, kx_, ky_);
        }
    }

    function _edDouble(
        uint256 x,
        uint256 y,
        uint256 u,
        uint256 v
    )
        private
        pure
        returns (uint256 ox, uint256 oy, uint256 ou, uint256 ov)
    {
        unchecked {
            uint256 xx =
                mulmod(x, v, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
            uint256 yy =
                mulmod(y, u, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
            uint256 zz =
                mulmod(u, v, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
            uint256 xx2 =
                mulmod(xx, xx, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
            uint256 yy2 =
                mulmod(yy, yy, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
            uint256 xxyy =
                mulmod(xx, yy, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
            uint256 zz2 =
                mulmod(zz, zz, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed);
            ox = xxyy + xxyy;
            ou = yy2 - xx2 + 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed;
            oy = xx2 + yy2;
            ov = addmod(
                zz2 + zz2,
                0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffda - ou,
                0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
            );
        }
    }

    function _computeTables(uint256[8][3][2] memory tables, uint256 kx, uint256 ky) private pure {
        unchecked {
            uint256 kkx;
            uint256 kky;
            uint256 kku;
            uint256 kkv;
            (kkx, kky, kku, kkv) = _edDouble(kx, ky, 1, 1);
            (kkx, kky, kku, kkv) = _edDouble(kkx, kky, kku, kkv);
            (kkx, kky, kku, kkv) = _edDouble(kkx, kky, kku, kkv);
            uint256 cprod = 1;
            uint256[8][3][2] memory tables_ = tables;
            for (uint256 i = 0;; i++) {
                uint256 cs;
                uint256 cd;
                uint256 ct;
                uint256 c2z;
                {
                    uint256 cx = mulmod(
                        kkx, kkv, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
                    );
                    uint256 cy = mulmod(
                        kky, kku, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
                    );
                    uint256 cz = mulmod(
                        kku, kkv, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
                    );
                    ct = mulmod(
                        kkx, kky, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
                    );
                    cs = cy + cx;
                    cd = cy - cx
                        + 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed;
                    c2z = cz + cz;
                }
                tables_[1][0][i] = cs;
                tables_[1][1][i] = cd;
                tables_[1][2][i] = mulmod(
                    ct,
                    0x2406d9dc56dffce7198e80f2eef3d13000e0149a8283b156ebd69b9426b2f159,
                    0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
                );
                tables_[0][0][i] = c2z;
                tables_[0][1][i] = cprod;
                cprod = mulmod(
                    cprod, c2z, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
                );
                if (i == 7) {
                    break;
                }
                uint256 ab = mulmod(
                    cs, ky + kx, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
                );
                uint256 aa = mulmod(
                    cd,
                    ky + 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed - kx,
                    0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
                );
                uint256 ac = mulmod(
                    ct,
                    mulmod(
                        mulmod(
                            kx,
                            ky,
                            0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
                        ),
                        0x2406d9dc56dffce7198e80f2eef3d13000e0149a8283b156ebd69b9426b2f159,
                        0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
                    ),
                    0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
                );
                kkx = ab - aa + 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed;
                kku = addmod(
                    c2z, ac, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
                );
                kky = ab + aa;
                kkv = addmod(
                    c2z,
                    0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed - ac,
                    0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
                );
            }
            uint256 t;
            (cprod, t) = pow22501(cprod);
            cprod = mulmod(
                cprod, cprod, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
            );
            cprod = mulmod(
                cprod, cprod, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
            );
            cprod = mulmod(
                cprod, cprod, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
            );
            cprod = mulmod(
                cprod, cprod, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
            );
            cprod = mulmod(
                cprod, cprod, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
            );
            cprod = mulmod(
                cprod, t, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
            );
            for (uint256 i = 7;; i--) {
                uint256 cinv = mulmod(
                    cprod,
                    tables_[0][1][i],
                    0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
                );
                tables_[1][0][i] = mulmod(
                    tables_[1][0][i],
                    cinv,
                    0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
                );
                tables_[1][1][i] = mulmod(
                    tables_[1][1][i],
                    cinv,
                    0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
                );
                tables_[1][2][i] = mulmod(
                    tables_[1][2][i],
                    cinv,
                    0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
                );
                if (i == 0) {
                    break;
                }
                cprod = mulmod(
                    cprod,
                    tables_[0][0][i],
                    0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
                );
            }
            tables_[0] = [
                [
                    0x43e7ce9d19ea5d329385a44c321ea16167c996e37dc6070c97de49e37ac61db9,
                    0x40cff34425d8ec30a3bb74ba58cd5854fa1e38186ad0d31ebc8ae251ceb2c97e,
                    0x459bd27046e8dd45aea7008db87a5a8f7906779253d64523589518599fdfbf4b,
                    0x69fdd1e28c23cc3894d0c8ff90e76f6d5b6e4c2e620136d04dd83c4a51581ab9,
                    0x54dceb3413ce5cfa11196dfc960b6edaf4b380c6d4d2378419cc0279ba49c5f3,
                    0x4e24184dd71a3d77eef3729f7f8cf7c17224cf40aa7b9548b9942f3c5084ceed,
                    0x5a0e5aab20262674ae1175761cbf5e889b52a55fd7ac5027c228cebdc8d2360a,
                    0x26239334073e9b38c62859556d451c3dcc8d30e84b361174f488eadde2cf17d9
                ],
                [
                    0x227e97c94c7c0933d2e0c21a3447c504fe9ccf82e8a05f59ce881c82eba0489f,
                    0x226a3e0ecc4afec6fd0d288413014a9dbddecf06c1a2f0bb702ba77c613d8209,
                    0x34d7efc851d45c5e71efeb0f235b794691de6228877569b3a8d52bf058b8a4a0,
                    0x3c1f5fb3ca7166fce1471c9b752b6d28c56301ad7b65e8451b2c8c5526726e12,
                    0x6102416cf02f02ff5be75275f55f28db89b2a9d2456b860ce22fc0e5031f7cc5,
                    0x40adf677f1bfdae057f0fd179c12617918ddaa2891a6530fb1a4294fa8665490,
                    0x61936f3c415609046187b8baa978cbc9b47893363ae5a3cc7d909f3635ae7f48,
                    0x562a9662b6ec47f9e979d473c02b51e4423368238c58ddb52f0e5c6a180e6410
                ],
                [
                    0x3788bdb44f8632d42d0dbee5eea1acc6136cf411e655624f55e48902c3bd5534,
                    0x6190cf2c2a7b5ad769d594a82844f23b4167fa7c8ac30e51aa6cfbebdcd4b945,
                    0x65f7787096be9204123a71f3ac88a87be1513217737d6a1e2f3a13a43d7e3a9a,
                    0x23af32dbfa67975536479a7a7ce74a02142147fac0480187f1f13349cda1f2d,
                    0x64fc44b7fc6841bddb0ced8b8b0fe6759137ef87ee96651215fc1dbcd25c64dc,
                    0x1434aa3748b701d5b69df3d7d340c1fe3f6b9c1efc617484caadb47e382f4475,
                    0x457a6da8c962ef35f2b217423e5844e9d23534527e8ea4290d24e3ddf21720c6,
                    0x63b9540ceb60ccb51e4d989d956e053cf2511837efb79089d2ff40284202c53d
                ]
            ];
        }
    }

    function verify(bytes32 k, bytes32 r, bytes32 s, bytes memory m) internal pure returns (bool) {
        unchecked {
            uint256 hh;
            // Step 1: compute SHA-512(R, A, M)
            {
                bytes memory rs = new bytes(k.length + r.length + m.length);
                for (uint256 i = 0; i < r.length; i++) {
                    rs[i] = r[i];
                }
                for (uint256 i = 0; i < k.length; i++) {
                    rs[i + 32] = k[i];
                }
                for (uint256 i = 0; i < m.length; i++) {
                    rs[i + 64] = m[i];
                }
                uint64[8] memory result = Sha512.hash(rs);

                uint256 h0 = uint256(result[0]) | uint256(result[1]) << 64 | uint256(result[2])
                    << 128 | uint256(result[3]) << 192;

                h0 = ((h0 & 0xff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff) << 8)
                    | ((h0 & 0xff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00)
                        >> 8);
                h0 = ((h0 & 0xffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff) << 16)
                    | ((h0 & 0xffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000)
                        >> 16);
                h0 = ((h0 & 0xffffffff00000000ffffffff00000000ffffffff00000000ffffffff) << 32)
                    | ((h0 & 0xffffffff00000000ffffffff00000000ffffffff00000000ffffffff00000000)
                        >> 32);

                uint256 h1 = uint256(result[4]) | uint256(result[5]) << 64 | uint256(result[6])
                    << 128 | uint256(result[7]) << 192;

                h1 = ((h1 & 0xff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff) << 8)
                    | ((h1 & 0xff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00)
                        >> 8);
                h1 = ((h1 & 0xffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff) << 16)
                    | ((h1 & 0xffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000)
                        >> 16);
                h1 = ((h1 & 0xffffffff00000000ffffffff00000000ffffffff00000000ffffffff) << 32)
                    | ((h1 & 0xffffffff00000000ffffffff00000000ffffffff00000000ffffffff00000000)
                        >> 32);
                hh = addmod(
                    h0,
                    mulmod(
                        h1,
                        0xffffffffffffffffffffffffffffffec6ef5bf4737dcf70d6ec31748d98951d,
                        0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed
                    ),
                    0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed
                );
            }
            // Step 2: unpack k
            k = bytes32(
                ((uint256(k) & 0xff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff)
                        << 8)
                    | ((uint256(k)
                            & 0xff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00)
                        >> 8)
            );
            k = bytes32(
                ((uint256(k) & 0xffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff)
                        << 16)
                    | ((uint256(k)
                            & 0xffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000)
                        >> 16)
            );
            k = bytes32(
                ((uint256(k) & 0xffffffff00000000ffffffff00000000ffffffff00000000ffffffff) << 32)
                    | ((uint256(k)
                            & 0xffffffff00000000ffffffff00000000ffffffff00000000ffffffff00000000)
                        >> 32)
            );
            k = bytes32(
                ((uint256(k) & 0xffffffffffffffff0000000000000000ffffffffffffffff) << 64)
                    | ((uint256(k)
                            & 0xffffffffffffffff0000000000000000ffffffffffffffff0000000000000000)
                        >> 64)
            );
            k = bytes32((uint256(k) << 128) | (uint256(k) >> 128));
            // Verify s (moved before ky/kx to reduce stack pressure)
            s = bytes32(
                ((uint256(s) & 0xff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff)
                        << 8)
                    | ((uint256(s)
                            & 0xff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00)
                        >> 8)
            );
            s = bytes32(
                ((uint256(s) & 0xffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff)
                        << 16)
                    | ((uint256(s)
                            & 0xffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000)
                        >> 16)
            );
            s = bytes32(
                ((uint256(s) & 0xffffffff00000000ffffffff00000000ffffffff00000000ffffffff) << 32)
                    | ((uint256(s)
                            & 0xffffffff00000000ffffffff00000000ffffffff00000000ffffffff00000000)
                        >> 32)
            );
            s = bytes32(
                ((uint256(s) & 0xffffffffffffffff0000000000000000ffffffffffffffff) << 64)
                    | ((uint256(s)
                            & 0xffffffffffffffff0000000000000000ffffffffffffffff0000000000000000)
                        >> 64)
            );
            s = bytes32((uint256(s) << 128) | (uint256(s) >> 128));
            if (uint256(s) >= 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed) {
                return false;
            }
            // Step 3: compute multiples of k
            uint256[8][3][2] memory tables;
            {
                (bool valid, uint256 kx, uint256 ky) = _unpackKey(k);
                if (!valid) return false;
                _computeTables(tables, kx, ky);
            }
            // Step 4: compute s*G - h*A
            {
                uint256 ss = uint256(s) << 3;
                uint256 hhh =
                    hh + 0x80000000000000000000000000000000a6f7cef517bce6b2c09318d2e7ae9f60;
                uint256 vvx = 0;
                uint256 vvu = 1;
                uint256 vvy = 1;
                uint256 vvv = 1;
                for (uint256 i = 252;; i--) {
                    uint256 bit = 8 << i;
                    if ((ss & bit) != 0) {
                        uint256 ws;
                        uint256 wd;
                        uint256 wz;
                        uint256 wt;
                        {
                            uint256 wx = mulmod(
                                vvx,
                                vvv,
                                0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
                            );
                            uint256 wy = mulmod(
                                vvy,
                                vvu,
                                0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
                            );
                            ws = wy + wx;
                            wd = wy - wx
                                + 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed;
                            wz = mulmod(
                                vvu,
                                vvv,
                                0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
                            );
                            wt = mulmod(
                                vvx,
                                vvy,
                                0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
                            );
                        }
                        uint256 j = (ss >> i) & 7;
                        ss &= ~(7 << i);
                        uint256[8][3][2] memory tables_ = tables;
                        uint256 aa = mulmod(
                            wd,
                            tables_[0][1][j],
                            0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
                        );
                        uint256 ab = mulmod(
                            ws,
                            tables_[0][0][j],
                            0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
                        );
                        uint256 ac = mulmod(
                            wt,
                            tables_[0][2][j],
                            0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
                        );
                        vvx = ab - aa
                            + 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed;
                        vvu = wz + ac;
                        vvy = ab + aa;
                        vvv = wz - ac
                            + 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed;
                    }
                    if ((hhh & bit) != 0) {
                        uint256 ws;
                        uint256 wd;
                        uint256 wz;
                        uint256 wt;
                        {
                            uint256 wx = mulmod(
                                vvx,
                                vvv,
                                0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
                            );
                            uint256 wy = mulmod(
                                vvy,
                                vvu,
                                0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
                            );
                            ws = wy + wx;
                            wd = wy - wx
                                + 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed;
                            wz = mulmod(
                                vvu,
                                vvv,
                                0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
                            );
                            wt = mulmod(
                                vvx,
                                vvy,
                                0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
                            );
                        }
                        uint256 j = (hhh >> i) & 7;
                        hhh &= ~(7 << i);
                        uint256[8][3][2] memory tables_ = tables;
                        uint256 aa = mulmod(
                            wd,
                            tables_[1][0][j],
                            0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
                        );
                        uint256 ab = mulmod(
                            ws,
                            tables_[1][1][j],
                            0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
                        );
                        uint256 ac = mulmod(
                            wt,
                            tables_[1][2][j],
                            0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
                        );
                        vvx = ab - aa
                            + 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed;
                        vvu = wz - ac
                            + 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed;
                        vvy = ab + aa;
                        vvv = wz + ac;
                    }
                    if (i == 0) {
                        uint256 ws;
                        uint256 wd;
                        uint256 wz;
                        uint256 wt;
                        {
                            uint256 wx = mulmod(
                                vvx,
                                vvv,
                                0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
                            );
                            uint256 wy = mulmod(
                                vvy,
                                vvu,
                                0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
                            );
                            ws = wy + wx;
                            wd = wy - wx
                                + 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed;
                            wz = mulmod(
                                vvu,
                                vvv,
                                0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
                            );
                            wt = mulmod(
                                vvx,
                                vvy,
                                0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
                            );
                        }
                        uint256 j = hhh & 7;
                        uint256[8][3][2] memory tables_ = tables;
                        uint256 aa = mulmod(
                            wd,
                            tables_[1][0][j],
                            0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
                        );
                        uint256 ab = mulmod(
                            ws,
                            tables_[1][1][j],
                            0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
                        );
                        uint256 ac = mulmod(
                            wt,
                            tables_[1][2][j],
                            0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
                        );
                        vvx = ab - aa
                            + 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed;
                        vvu = wz - ac
                            + 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed;
                        vvy = ab + aa;
                        vvv = wz + ac;
                        break;
                    }
                    {
                        uint256 xx = mulmod(
                            vvx,
                            vvv,
                            0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
                        );
                        uint256 yy = mulmod(
                            vvy,
                            vvu,
                            0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
                        );
                        uint256 zz = mulmod(
                            vvu,
                            vvv,
                            0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
                        );
                        uint256 xx2 = mulmod(
                            xx,
                            xx,
                            0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
                        );
                        uint256 yy2 = mulmod(
                            yy,
                            yy,
                            0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
                        );
                        uint256 xxyy = mulmod(
                            xx,
                            yy,
                            0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
                        );
                        uint256 zz2 = mulmod(
                            zz,
                            zz,
                            0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
                        );
                        vvx = xxyy + xxyy;
                        vvu = yy2 - xx2
                            + 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed;
                        vvy = xx2 + yy2;
                        vvv = addmod(
                            zz2 + zz2,
                            0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffda
                                - vvu,
                            0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
                        );
                    }
                }
                // Step 5: compare the points (combined with Step 4 to scope vvx/vvu/vvy/vvv)
                (uint256 vi, uint256 vj) = pow22501(
                    mulmod(
                        vvu, vvv, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
                    )
                );
                vi = mulmod(
                    vi, vi, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
                );
                vi = mulmod(
                    vi, vi, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
                );
                vi = mulmod(
                    vi, vi, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
                );
                vi = mulmod(
                    vi, vi, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
                );
                vi = mulmod(
                    vi, vi, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
                );
                vi = mulmod(
                    vi, vj, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
                );
                vvx = mulmod(
                    vvx,
                    mulmod(
                        vi, vvv, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
                    ),
                    0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
                );
                vvy = mulmod(
                    vvy,
                    mulmod(
                        vi, vvu, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
                    ),
                    0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
                );
                bytes32 vr = bytes32(vvy | (vvx << 255));
                vr = bytes32(
                    ((uint256(vr)
                                & 0xff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff)
                            << 8)
                        | ((uint256(vr)
                                & 0xff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00)
                            >> 8)
                );
                vr = bytes32(
                    ((uint256(vr) & 0xffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff)
                            << 16)
                        | ((uint256(vr)
                                & 0xffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000)
                            >> 16)
                );
                vr = bytes32(
                    ((uint256(vr) & 0xffffffff00000000ffffffff00000000ffffffff00000000ffffffff)
                            << 32)
                        | ((uint256(vr)
                                & 0xffffffff00000000ffffffff00000000ffffffff00000000ffffffff00000000)
                            >> 32)
                );
                vr = bytes32(
                    ((uint256(vr) & 0xffffffffffffffff0000000000000000ffffffffffffffff) << 64)
                        | ((uint256(vr)
                                & 0xffffffffffffffff0000000000000000ffffffffffffffff0000000000000000)
                            >> 64)
                );
                vr = bytes32((uint256(vr) << 128) | (uint256(vr) >> 128));
                return vr == r;
            }
        }
    }

}
