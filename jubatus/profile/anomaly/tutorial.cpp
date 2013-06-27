#include "../../server/common/util.hpp"
#include "../../server/server/anomaly_types.hpp"
#include "../../server/server/anomaly_serv.hpp"
#include "../../server/framework/server_helper.hpp"
#include "../../server/framework/server_util.hpp"
#include <cassert>
#include <cerrno>
#include <pficommon/text/csv.h>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <string>

using pfi::text::csv_parser;
using jubatus::server::anomaly_serv;
using jubatus::server::framework::get_conf;
using jubatus::server::framework::server_argv;
using jubatus::server::framework::server_helper;

namespace {

struct to_d {} d;

double operator->*(char const* s, to_d)
{
    errno = 0;
    double ret = std::strtod(s, 0);
    assert(errno);
    return ret;
}

float const inf = 1.0 / 0.0;

}

int main(int argc, char* argv[])
{
    server_argv argv_(argc, argv, "anomaly");
    server_helper<anomaly_serv> s(argv_, true);
    anomaly_serv& anomaly = *s.server();

    std::ifstream f("kddcup.data_10_percent.txt");
    if (!f) {
        std::cerr << "cannot open datafile\n";
    }
    csv_parser csv(f);
    while (csv.next()) {
        csv_parser::row_type const& row = csv.get();
        assert(row.size() == 42);
        // if (row.size() != 42)
        //     continue;
        double duration = row[0] ->* d;
        char const* protocol_type = row[1];
        char const* service = row[2];
        char const* flag = row[3];
        double src_bytes = row[4] ->* d;
        double dst_bytes = row[5] ->* d;
        char const* land = row[6];
        double wrong_fragment = row[7] ->* d;
        double urgent = row[8] ->* d;
        double hot = row[9] ->*d;
        double num_failed_logins = row[10] ->* d;        
        char const* logged_in = row[11];
        double num_compromised = row[12] ->* d;
        double root_shell = row[13] ->* d;
        double su_attempted = row[14] ->* d;
        double num_root = row[15] ->* d;
        double num_file_creations = row[16] ->* d;
        double num_shells = row[17] ->* d;
        double num_access_files = row[18] ->* d;
        double num_outbound_cmds = row[19] ->* d;
        char const* is_host_login = row[20];
        char const* is_guest_login = row[21];
        double count = row[22] ->* d;
        double srv_count = row[23] ->* d;
        double serror_rate = row[24] ->* d;
        double srv_serror_rate = row[25] ->* d;
        double rerror_rate = row[26] ->* d;
        double srv_rerror_rate = row[27] ->* d;
        double same_srv_rate = row[28] ->* d;
        double diff_srv_rate = row[29] ->* d;
        double srv_diff_host_rate = row[30] ->* d;
        double dst_host_count = row[31] ->* d;
        double dst_host_srv_count = row[32] ->* d;
        double dst_host_same_srv_rate = row[33] ->* d;
        double dst_host_diff_srv_rate = row[34] ->* d;
        double dst_host_same_src_port_rate = row[35] ->* d;
        double dst_host_srv_diff_host_rate = row[36] ->* d;
        double dst_host_serror_rate = row[37] ->* d;
        double dst_host_srv_serror_rate = row[38] ->* d;
        double dst_host_rerror_rate = row[39] ->* d;
        double dst_host_srv_rerror_rate = row[40] ->* d;
        char const* label = row[41];

        jubatus::datum datum;
#define push_s(name) datum.string_values.push_back(std::make_pair(#name, name))
#define push_d(name) datum.num_values.push_back(std::make_pair(#name, name))
        push_d(duration);
        push_s(protocol_type);
        push_s(service);
        push_s(flag);
        push_d(src_bytes);
        push_d(dst_bytes);
        push_s(land);
        push_d(wrong_fragment);
        push_d(urgent);
        push_d(hot);
        push_d(num_failed_logins);
        push_s(logged_in);
        push_d(num_compromised);
        push_d(root_shell);
        push_d(su_attempted);
        push_d(num_root);
        push_d(num_file_creations);
        push_d(num_shells);
        push_d(num_access_files);
        push_d(num_outbound_cmds);
        push_s(is_host_login);
        push_s(is_guest_login);
        push_d(count);
        push_d(srv_count);
        push_d(serror_rate);
        push_d(srv_serror_rate);
        push_d(rerror_rate);
        push_d(srv_rerror_rate);
        push_d(same_srv_rate);
        push_d(diff_srv_rate);
        push_d(srv_diff_host_rate);
        push_d(dst_host_count);
        push_d(dst_host_srv_count);
        push_d(dst_host_same_srv_rate);
        push_d(dst_host_diff_srv_rate);
        push_d(dst_host_same_src_port_rate);
        push_d(dst_host_srv_diff_host_rate);
        push_d(dst_host_serror_rate);
        push_d(dst_host_srv_serror_rate);
        push_d(dst_host_rerror_rate);
        push_d(dst_host_srv_rerror_rate);

        std::pair<std::string, float> ret = anomaly.add(datum);
        if (ret.second != inf && ret.second != 1)
            std::cout << ret.first << '\t' << ret.second << '\t' << label << std::endl;
    }
}
