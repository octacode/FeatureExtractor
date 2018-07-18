package org.argus.feature_extractor

import scala.collection.mutable

package object AllAssets {
  val hashMap: mutable.LinkedHashMap[String, Integer] = mutable.LinkedHashMap(
    (".so", 0),
    (".lnk", 0),
    (".exe", 0),
    (".zip", 0),
    (".rar", 0),
    (".tar", 0),
    (".7z", 0),
    ("hasContacts", 0),
    ("fakeExtension", 0)
  )
}
