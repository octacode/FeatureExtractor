package org.argus.feature_extractor.random

import org.argus.amandroid.alir.componentSummary.ApkYard
import org.argus.amandroid.alir.pta.model.AndroidModelCallHandler
import org.argus.amandroid.alir.pta.reachingFactsAnalysis.{AndroidReachingFactsAnalysis, AndroidReachingFactsAnalysisConfig}
import org.argus.amandroid.alir.pta.summaryBasedAnalysis.AndroidSummaryProvider
import org.argus.amandroid.alir.taintAnalysis.{AndroidDataDependentTaintAnalysis, DataLeakageAndroidSourceAndSinkManager}
import org.argus.amandroid.core.decompile.{DecompileLayout, DecompileStrategy, DecompilerSettings}
import org.argus.amandroid.core.parser.IntentFilterDataBase
import org.argus.amandroid.core.{AndroidGlobalConfig, ApkGlobal}
import org.argus.feature_extractor.{AllPermissions, AllReceiver}
import org.argus.jawa.alir.Context
import org.argus.jawa.alir.cfg.{ICFGNode, InterProceduralControlFlowGraph}
import org.argus.jawa.alir.dda.InterProceduralDataDependenceAnalysis
import org.argus.jawa.alir.pta.PTAResult
import org.argus.jawa.core.util._
import org.argus.jawa.core.{ClassLoadManager, DefaultReporter}

import scala.sys.process._
import scala.io.Source._
import scala.xml.XML

object MyTester {
  var apk: ApkGlobal = _
  var permMap: MLinkedMap[String, Integer] = AllPermissions.hashMap
  var recvMap: MLinkedMap[String, Integer] = AllReceiver.hashMap
  var path: String = _
  var outputUri: FileResourceUri = _
  var codeUri: FileResourceUri = _

  def main(args: Array[String]): Unit = {
    if (args.length != 2) {
      println("usage: apk_path output_path")
      return
    }
    path = args(1)
    val fileUri = FileUtil.toUri(args(0))
    outputUri = FileUtil.toUri(args(1))
    val reporter = new DefaultReporter
    val yard = new ApkYard(reporter)
    val layout = DecompileLayout(outputUri)
    val strategy = DecompileStrategy(layout)
    val settings = DecompilerSettings(debugMode = true, forceDelete = true, strategy, reporter)
    apk = yard.loadApk(fileUri, settings, collectInfo = true, resolveCallBack = false)
    var name = apk.model.getAppName.replace(".apk", "")
    codeUri = outputUri + name + "/"
    codeUri.replace("file:", "")
    val component = apk.model.getComponents.head // get any component you want to perform analysis
    apk.model.getEnvMap.get(component) match {
      case Some((esig, _)) =>
        val ep = apk.getMethod(esig).get
        val initialfacts = AndroidReachingFactsAnalysisConfig.getInitialFactsForMainEnvironment(ep)
        val icfg = new InterProceduralControlFlowGraph[ICFGNode]
        val ptaresult = new PTAResult
        val sp = new AndroidSummaryProvider(apk)
        val analysis = new AndroidReachingFactsAnalysis(
          apk, icfg, ptaresult, new AndroidModelCallHandler, sp.getSummaryManager, new ClassLoadManager,
          AndroidReachingFactsAnalysisConfig.resolve_static_init,
          timeout = None)
        val idfg = analysis.build(ep, initialfacts, new Context(apk.nameUri))
        val iddResult = InterProceduralDataDependenceAnalysis(apk, idfg)
        val ssm = new DataLeakageAndroidSourceAndSinkManager(AndroidGlobalConfig.settings.sas_file)
        val taint_analysis_result = AndroidDataDependentTaintAnalysis(yard, iddResult, idfg.ptaresult, ssm)

      case None =>
        yard.reporter.error("TaintAnalysis", "Component " + component + " did not have environment! Some package or name mismatch maybe in the Manifest file.")
    }

    val permissions = apk.model.getUsesPermissions
    val receivers = apk.model.getIntentFilterDB
    val isNumberPresent = numberFinder()
    checkAllFilesType()
    //modAll(permissions)(permMap)
    //modAllRecv(receivers)(recvMap)
    //assetAnalyser()
  }

  def assetAnalyser(): Unit = {
    val so_files = FileUtil.listFiles(codeUri, ".so", recursive = true)
    val lnk_file = FileUtil.listFiles(codeUri, ".lnk", recursive = true)
    val exe_file = FileUtil.listFiles(codeUri, ".exe", recursive = true)
    val zip_file = FileUtil.listFiles(codeUri, ".zip", recursive = true)
    val tar_file = FileUtil.listFiles(codeUri, ".tar", recursive = true)
    val rar_file = FileUtil.listFiles(codeUri, ".rar", recursive = true)
    val sevenz_file = FileUtil.listFiles(codeUri, ".7z", recursive = true)
    val areContacts = numberFinder()
    val isExtension = checkAllFilesType()
  }

  // Number fetcher
  def numberFinder(): Boolean = {
    val xmlFiles = FileUtil.listFiles(codeUri, ext = ".xml", recursive = true)
    xmlFiles.foreach {
      uri => {
        try {
          var xml = XML.loadFile(uri.replaceAll("file:", ""))
          var text = xml.text
          var lengthCounter = 0
          for (index <- 0 until text.length) {
            if (lengthCounter > 5) return true
            else if (Character.isDigit(text.charAt(index)))
              lengthCounter = lengthCounter + 1
            else
              lengthCounter = 0
          }
        } catch {
          case ex: Exception =>
        }
      }
    }
    false
  }

  def checkAllFilesType(): Boolean = {
    val files = FileUtil.listFiles(codeUri + "assets/", "", recursive = true)
    files.foreach {
      uri => {
        val cmd = "file -z " + uri.replace("file:", "")
        val exitCode = cmd.!
        //zip, rar, lsb shared object, executable
        if (exitCode.toString.toLowerCase().contains("zip") || exitCode.toString.toLowerCase().contains("rar") || exitCode.toString.toLowerCase().contains("lsb") || exitCode.toString.toLowerCase().contains("executable"))
          return true
      }
    }
    false
  }

  def modAllRecv(item: IntentFilterDataBase)(hashMap: MLinkedMap[String, Integer]): Unit = {
    val map = item.getIntentFmap
    map.foreach {
      cray => {
        cray._2.foreach {
          lie => {
            modAll(lie.getActions)(hashMap)
          }
        }
      }
    }
    printMap(hashMap)
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

  def checkForPayment(): Boolean = {
    var value = codeUri + "third_party_libs.txt"
    val lines = fromFile(codeUri.replace("file:", ""))
    var itr = lines.getLines()
    itr.foreach {
      lib => {
        if ()
      }
    }
  }
}