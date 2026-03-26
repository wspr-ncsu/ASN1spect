/**
 * Copyright 2013-2023 Software Radio Systems Limited
 *
 * This file is part of srsRAN.
 *
 * srsRAN is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * srsRAN is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * A copy of the GNU Affero General Public License can be found in
 * the LICENSE file in the top-level directory of this distribution
 * and at http://www.gnu.org/licenses/.
 *
 */

/*******************************************************************************
 *
 *                     3GPP TS ASN1 S1AP v16.1.0 (2020-03)
 *
 ******************************************************************************/

#include "asn1_utils.h"
#include <cstdio>
#include <stdarg.h>

namespace asn1 {
namespace s1ap {

/*******************************************************************************
 *                             Constant Definitions
 ******************************************************************************/

/*******************************************************************************
 *                              Struct Definitions
 ******************************************************************************/

// INTEGER (0..16777215) ::= INTEGER (0..16777215)
using enb_ue_s1ap_id_t = integer<uint32_t, 0, 16777215, false, true>;

// INTEGER (0..4294967295) ::= INTEGER (0..4294967295)
using mme_ue_s1ap_id_t = integer<uint64_t, 0, 4294967295, false, true>;

// PrivateIE-ID ::= CHOICE
struct private_ie_id_c {
  struct types_opts {
    enum options { local, global, nulltype } value;

    const char* to_string() const;
  };
  typedef enumerated<types_opts> types;

  // choice methods
  private_ie_id_c() = default;
  void        set(types::options e = types::nulltype);
  types       type() const { return type_; }
  SRSASN_CODE pack(bit_ref& bref) const;
  SRSASN_CODE unpack(cbit_ref& bref);
  void        to_json(json_writer& j) const;
  // getters
  uint32_t& local()
  {
    assert_choice_type(types::local, type_, "PrivateIE-ID");
    return c;
  }
  const uint32_t& local() const
  {
    assert_choice_type(types::local, type_, "PrivateIE-ID");
    return c;
  }
  uint32_t& set_local();
  void      set_global();

private:
  types    type_;
  uint32_t c;
};

// PrivateIE-Field{S1AP-PRIVATE-IES : IEsSetParam} ::= SEQUENCE{{S1AP-PRIVATE-IES}}
template <class ies_set_paramT_>
struct private_ie_field_s {
  private_ie_id_c                   id;
  crit_e                            crit;
  typename ies_set_paramT_::value_c value;

  SRSASN_CODE pack(bit_ref& bref) const;
  SRSASN_CODE unpack(cbit_ref& bref);
  void        to_json(json_writer& j) const;
};

// PrivateIE-Container{S1AP-PRIVATE-IES : IEsSetParam} ::= SEQUENCE (SIZE (1..65535)) OF PrivateIE-Field
template <class ies_set_paramT_>
using private_ie_container_l = dyn_seq_of<private_ie_field_s<ies_set_paramT_>, 1, 65535, true>;

// ProtocolIE-FieldPair{S1AP-PROTOCOL-IES-PAIR : IEsSetParam} ::= SEQUENCE{{S1AP-PROTOCOL-IES-PAIR}}
template <class ies_set_paramT_>
struct protocol_ie_field_pair_s {
  uint32_t                                 id = 0;
  crit_e                                   first_crit;
  typename ies_set_paramT_::first_value_c  first_value;
  crit_e                                   second_crit;
  typename ies_set_paramT_::second_value_c second_value;

  SRSASN_CODE pack(bit_ref& bref) const;
  SRSASN_CODE unpack(cbit_ref& bref);
  void        to_json(json_writer& j) const;
  bool        load_info_obj(const uint32_t& id_);
};

// ProtocolIE-ContainerPair{S1AP-PROTOCOL-IES-PAIR : IEsSetParam} ::= SEQUENCE (SIZE (0..65535)) OF ProtocolIE-FieldPair
template <class ies_set_paramT_>
using protocol_ie_container_pair_l = dyn_seq_of<protocol_ie_field_pair_s<ies_set_paramT_>, 0, 65535, true>;

// ActivatedCellsList-Item ::= SEQUENCE
struct activ_cells_list_item_s {
  bool                      ext = false;
  unbounded_octstring<true> cell_id;
  // ...

  // sequence methods
  SRSASN_CODE pack(bit_ref& bref) const;
  SRSASN_CODE unpack(cbit_ref& bref);
  void        to_json(json_writer& j) const;
};

// ActivatedCellsList ::= SEQUENCE (SIZE (0..256)) OF ActivatedCellsList-Item
using activ_cells_list_l = dyn_array<activ_cells_list_item_s>;

// GUMMEI-ExtIEs ::= OBJECT SET OF S1AP-PROTOCOL-EXTENSION
using gummei_ext_ies_o = protocol_ext_empty_o;

// PLMNidentity ::= OCTET STRING
using plm_nid = fixed_octstring<3, true>;

// Additional-GUTI-ExtIEs ::= OBJECT SET OF S1AP-PROTOCOL-EXTENSION
using add_guti_ext_ies_o = protocol_ext_empty_o;

using gummei_ext_ies_container = protocol_ext_container_empty_l;

// GUMMEI ::= SEQUENCE
struct gummei_s {
  bool                     ext             = false;
  bool                     ie_exts_present = false;
  fixed_octstring<3, true> plmn_id;
  fixed_octstring<2, true> mme_group_id;
  fixed_octstring<1, true> mme_code;
  gummei_ext_ies_container ie_exts;
  // ...

  // sequence methods
  SRSASN_CODE pack(bit_ref& bref) const;
  SRSASN_CODE unpack(cbit_ref& bref);
  void        to_json(json_writer& j) const;
};
