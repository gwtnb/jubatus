// Jubatus: Online machine learning framework for distributed environment
// Copyright (C) 2012 Preferred Infrastracture and Nippon Telegraph and Telephone Corporation.
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License version 2.1 as published by the Free Software Foundation.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

#include "lof.hpp"

#include <string>
#include <utility>
#include <vector>
#include <gtest/gtest.h>
#include <pficommon/data/unordered_map.h>
#include <pficommon/text/json.h>
#include "../common/jsonconfig.hpp"
#include "../recommender/euclid_lsh.hpp"
#include "lof_storage.hpp"

using jubatus::storage::lof_storage;
using pfi::data::unordered_map;
using std::pair;
using std::string;
using std::vector;

namespace jubatus {
namespace anomaly {

namespace {

float calculate_lof(
    float lrd,
    const unordered_map<string, float>& neighbor_lrd) {
  float sum_neighbor_lrd = 0;
  for (unordered_map<string, float>::const_iterator it = neighbor_lrd.begin();
       it != neighbor_lrd.end(); ++it) {
    sum_neighbor_lrd += it->second;
  }

  return sum_neighbor_lrd / (neighbor_lrd.size() * lrd);
}
}

class lof_impl : public lof {
 public:
  lof_impl()
      : lof(lof_storage::config(),
            recommender::create_recommender(
                "euclid_lsh",
                jsonconfig::config(pfi::text::json::to_json(
                    recommender::euclid_lsh::config())))) {
    // make mock
    orig_.set("r1", "a1", 0.0);
    orig_.set("r1", "a2", 0.0);

    orig_.set("r2", "a1", 0.0);
    orig_.set("r2", "a2", 1.0);

    orig_.set("r3", "a1", 1.0);
    orig_.set("r3", "a1", -1.0);
  }

  float calc_anomaly_score(const sfv_t& query) const {
    unordered_map<string, float> neighbor_lrd;
    neighbor_lrd.insert(pair<string, float>("r1", 1.0));
    neighbor_lrd.insert(pair<string, float>("r2", 0.5));
    neighbor_lrd.insert(pair<string, float>("r3", 1.5));
    const float lrd = 2.0;
    return calculate_lof(lrd, neighbor_lrd);
  }

  float calc_anomaly_score(const string& id) const {
    unordered_map<string, float> neighbor_lrd;
    neighbor_lrd.insert(pair<string, float>("r1", 1.0));
    neighbor_lrd.insert(pair<string, float>("r2", 0.5));
    neighbor_lrd.insert(pair<string, float>("r3", 1.5));
    const float lrd = neighbor_lrd[id];
    return calculate_lof(lrd, neighbor_lrd);
  }

  void clear() {
  }

  void clear_row(const string& id) {
  }

  void update_row(const string& id, const sfv_diff_t& diff) {
  }

  void get_all_row_ids(vector<string>& ids) const {
    ids.clear();
    ids.push_back("r1");
    ids.push_back("r2");
    ids.push_back("r3");
  }

  string type() const {
    return string("lof_impl");
  }

  bool save_impl(std::ostream&) {
    return true;
  }

  bool load_impl(std::istream&) {
    return true;
  }

  storage::anomaly_storage_base* get_storage() {
    return NULL;
  }

  const storage::anomaly_storage_base* get_const_storage() const {
    return NULL;
  }
};

TEST(lof, get_all_row_ids) {
  lof_impl l;
  std::vector<std::string> all_row_ids;
  l.get_all_row_ids(all_row_ids);
  ASSERT_EQ(3u, all_row_ids.size());
  EXPECT_EQ("r1", all_row_ids[0]);
  EXPECT_EQ("r2", all_row_ids[1]);
  EXPECT_EQ("r3", all_row_ids[2]);
}

TEST(lof, calc_anomaly_score) {
  lof_impl l;
  sfv_t q;
  float anomaly_score = 0;
  anomaly_score = l.calc_anomaly_score(q);
  EXPECT_EQ(0.5, anomaly_score);
}

TEST(lof, calc_anomaly_score2) {
  lof_impl l;
  const string id = "r2";
  const float anomaly_score = l.calc_anomaly_score(id);
  EXPECT_EQ(2.0, anomaly_score);
}

}  // namespace anomaly
}  // namespace jubatus
