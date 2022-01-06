//  Last update: 2021-12-06

#ifndef UAPKI_NS_UTIL_H
#define UAPKI_NS_UTIL_H


#include "uapki-ns.h"


using namespace std;


namespace UapkiNS {

namespace Util {

    string oidFromExtensionName (const string& key);
    string oidFromRdName (const string& key);
    string undecorateTime (const string& time);

}   //  end namespace Util

}   //  end namespace UapkiNS


#endif
