package org.argus.feature_extractor

import scala.collection.mutable

package object AllCustomFeatures {
  val hashMap: mutable.LinkedHashMap[String, Integer] = mutable.LinkedHashMap(
    ("isNumberPresent", 0),
    ("isPaymentSDKUsed", 0),
    ("isDangerousLibPresent", 0),
    ("isCheckingForEmulator", 0),
    ("isCheckingForInstalledApplications", 0),
    ("isTryingToHide", 0),
    ("isDeletingMessages", 0),
    ("isURLAnIp", 0)
  )
}
