package org.argus.feature_extractor.random

import org.argus.amandroid.alir.componentSummary.ApkYard
import org.argus.amandroid.core.ApkGlobal
import org.argus.amandroid.core.decompile.{DecompileLayout, DecompileStrategy, DecompilerSettings}
import org.argus.feature_extractor.{AllPermissions, AllReceiver}
import org.argus.jawa.core.DefaultReporter
import org.argus.jawa.core.util._

object MyTester {
  var apk: ApkGlobal = _
  var permMap: MLinkedMap[String, Integer] = AllPermissions.hashMap
  var recvMap: MLinkedMap[String, Integer] = AllReceiver.hashMap

  def main(args: Array[String]): Unit = {
    if (args.length != 2) {
      println("usage: apk_path output_path")
      return
    }
    val fileUri = FileUtil.toUri(args(0))
    val outputUri = FileUtil.toUri(args(1))
    val reporter = new DefaultReporter
    val yard = new ApkYard(reporter)
    val layout = DecompileLayout(outputUri)
    val strategy = DecompileStrategy(layout)
    val settings = DecompilerSettings(debugMode = true, forceDelete = true, strategy, reporter)
    apk = yard.loadApk(fileUri, settings, collectInfo = true, resolveCallBack = false)

    val permissions = apk.model.getUsesPermissions
    val certificates = apk.model.getCertificates
    val services = apk.model.getServices
    val receivers = apk.model.getReceivers
    modAll(permissions)(permMap)
  }

  def modAll(item: ISet[String])(hashMap: MLinkedMap[String, Integer]): Unit = {
    item.foreach {
      hello => {
        if (hashMap.contains(hello)) {
          hashMap.put(hello, 1)
        }
      }
    }
    printMap(hashMap)
  }

  def printMap(hashMap: MLinkedMap[String, Integer]): Unit = {
    var set = hashMap.keySet
    set.foreach {
      hello => {
        println(hello + "     " + hashMap(hello))
      }
    }
  }
}
