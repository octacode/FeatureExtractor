package org.argus.play.random

import java.io.PrintWriter

import org.argus.amandroid.alir.componentSummary.ApkYard
import org.argus.amandroid.core.decompile.{DecompileLayout, DecompileStrategy, DecompilerSettings}
import org.argus.jawa.alir.JawaAlirInfoProvider
import org.argus.jawa.core.DefaultReporter
import org.argus.jawa.core.util._

object MyTester {
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
    val apk = yard.loadApk(fileUri, settings, collectInfo = true, resolveCallBack = false)

    val permissions = apk.model.getUsesPermissions
    val certificates = apk.model.getCertificates

    val allMethods = apk.getApplicationClasses.map(c => c.getDeclaredMethods).reduce(_ ++ _)
        allMethods.foreach { m =>
          println(m.getSignature)
          println(m.retrieveCode)
          val cfg = JawaAlirInfoProvider.getCfg(m)
          cfg.toDot(new PrintWriter(System.out))
        }

//    printMe("Permissions")(permissions.toList)
  }

  def printMe(message: String)(item: List[String]): Unit = {
    println("\t\t"+message)
    item.foreach {
      hello => println(hello)
    }
  }
}
