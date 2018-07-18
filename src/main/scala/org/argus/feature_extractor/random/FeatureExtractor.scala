package org.argus.feature_extractor.random

import java.util.regex.Pattern

import org.argus.amandroid.alir.componentSummary.ApkYard
import org.argus.amandroid.alir.pta.model.AndroidModelCallHandler
import org.argus.amandroid.alir.pta.reachingFactsAnalysis.{AndroidReachingFactsAnalysis, AndroidReachingFactsAnalysisConfig}
import org.argus.amandroid.alir.pta.summaryBasedAnalysis.AndroidSummaryProvider
import org.argus.amandroid.alir.taintAnalysis.{AndroidDataDependentTaintAnalysis, DataLeakageAndroidSourceAndSinkManager}
import org.argus.amandroid.core.decompile.{DecompileLayout, DecompileStrategy, DecompilerSettings}
import org.argus.amandroid.core.parser.IntentFilterDataBase
import org.argus.amandroid.core.{AndroidGlobalConfig, ApkGlobal}
import org.argus.feature_extractor.{AllPermissions, AllReceiver, DangerousCalls, Libs}
import org.argus.jawa.alir.Context
import org.argus.jawa.alir.cfg.{ICFGNode, InterProceduralControlFlowGraph}
import org.argus.jawa.alir.dda.InterProceduralDataDependenceAnalysis
import org.argus.jawa.alir.pta.PTAResult
import org.argus.jawa.core.util._
import org.argus.jawa.core.{ClassLoadManager, DefaultReporter}

import scala.collection.mutable
import scala.io.Source._
import scala.sys.process._
import scala.xml.XML

object FeatureExtractor {
  private val urlPattern = Pattern.compile("(?:^|[\\W])((ht|f)tp(s?):\\/\\/|www\\.)" + "(([\\w\\-]+\\.){1,}?([\\w\\-.~]+\\/?)*" + "[\\p{Alnum}.,%_=?&#\\-+()\\[\\]\\*$~@!:/{};']*)", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL)
  var apk: ApkGlobal = _
  var permMap: MLinkedMap[String, Integer] = AllPermissions.hashMap
  var recvMap: MLinkedMap[String, Integer] = AllReceiver.hashMap
  var dangerApis: MLinkedMap[String, Integer] = DangerousCalls.hashMap
  var dangerousList: List[String] = Libs.harmfulLibs
  var paymentsList: List[String] = Libs.paymentLibs
  var codeUri: FileResourceUri = _
  var allCalls: MLinkedMap[String, Integer] = mutable.LinkedHashMap()

  def main(args: Array[String]): Unit = {
    if (args.length != 2) {
      println("usage: apk_path output_path")
      return
    }
    val fileUri = FileUtil.toUri("/home/shasha/Forked_Repo/NotificationHelper/app/build/outputs/apk/debug/app-debug.apk")
    var outputUri = FileUtil.toUri(args(1))
    val reporter = new DefaultReporter
    val yard = new ApkYard(reporter)
    val layout = DecompileLayout(outputUri)
    val strategy = DecompileStrategy(layout)
    val settings = DecompilerSettings(debugMode = true, forceDelete = true, strategy, reporter)
    apk = yard.loadApk(fileUri, settings, collectInfo = true, resolveCallBack = true)
    var name = apk.model.getAppName.replace(".apk", "")
    codeUri = outputUri + name + "/"
    codeUri.replace("file:", "")
    val component = apk.model.getComponents.head // get any component you want to perform analysis
    println(permMap.toString)
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
        taint_analysis_result.getTaintedPaths.foreach {
          path => {
            allCalls.put(path.getSink.descriptor.desc.replace(";.", ";->").replace(":(", "("), 0)
            allCalls.put(path.getSource.descriptor.desc.replace(";.", ";->").replace(":(", "("), 0)
          }
        }
      case None =>
    }

    val permissions = apk.model.getUsesPermissions
    val receivers = apk.model.getIntentFilterDB
    val isNumberPresent = numberFinder()
    val isPaymentSDKPresent = checkForPayment()

    modAll(permissions)(permMap)
    modAllRecv(receivers)(recvMap)
    assetAnalyser()
    
    modDangerousCall(allCalls)(dangerApis)

    // METHODWISE CODE ANALYSIS
    val allMethods = apk.getApplicationClasses.map(c => c.getDeclaredMethods).reduce(_ ++ _)
    allMethods.foreach { m =>
      val code = m.retrieveCode.toString

      //      println("isCheckingForEmulator: " + checkForEmulator(code))
      //      println("isCheckingInstalledApplications: " + isCheckingInstalledApplications(code))
      //      println("isTryingToHide: " + isTryingToHide(code))
      //      println("isDeletingMessages: " + isDeletingMessages(code))
      //      println("isURLAnIP: " + isUrlAnIpAddress(code))
    }
  }

  def isUrlAnIpAddress(code: String): Boolean = {
    var matcher = urlPattern.matcher(code)
    while (matcher.find) {
      var start = matcher.start(1)
      var end = matcher.end()
      var url = code.substring(start, end)
      var counter = 0
      url.foreach {
        a => {
          if (Character.isDigit(a)) counter = counter + 1
        }
      }
      if (counter > 7)
        return true
    }
    false
  }

  def checkForEmulator(code: String): Boolean = {
    //Check for emulator
    if (code.contains("android.os.Build.FINGERPRINT") && code.contains("startsWith") && code.contains("generic"))
      true
    else if (code.contains("android.os.Build.FINGERPRINT") && code.contains("android.os.Build.FINGERPRINT") && code.contains("unknown"))
      true
    else if (code.contains("android.os.Build.MODEL") && code.contains("contains") && code.contains("google_sdk"))
      true
    else if (code.contains("android.os.Build.MODEL") && code.contains("contains") && code.contains("Emulator"))
      true
    else if (code.contains("android.os.Build.MODEL") && code.contains("contains") && code.contains("Android SDK built for x86"))
      true
    else if (code.contains("android.os.Build.MANUFACTURER") && code.contains("contains") && code.contains("Genymotion"))
      true
    else if (code.contains("android.os.Build.BRAND") && code.contains("generic") && code.contains("startsWith") && code.contains("android.os.Build.DEVICE"))
      true
    else if (code.contains("android.os.Build.PRODUCT") && code.contains("google_sdk") && code.contains("android.os.Build.PRODUCT"))
      true
    else
      false
  }

  def isCheckingInstalledApplications(code: String): Boolean = {
    if (code.contains("getPackageManager") && code.contains("getInstalledApplications"))
      true
    else if (code.contains("getPackageManager") && code.contains("queryIntentActivities"))
      true
    else
      false
  }

  def isTryingToHide(code: String): Boolean = {
    if (code.contains("getPackageManager") && code.contains("android.content.ComponentName") && code.contains("setComponentEnabledSetting"))
      true
    else
      false
  }

  def isDeletingMessages(code: String): Boolean = {
    if (code.contains("content://sms") && code.contains("getContentResolver") && code.contains("delete"))
      true
    else
      false
  }

  def modDangerousCall(item: MLinkedMap[String, Integer])(hashMap: MLinkedMap[String, Integer]): Unit = {
    item.foreach {
      hello => {
        println(hello)
        hashMap.foreach {
          set => {
            var matchRatio = similarity(hello._1, set._1)
            if (matchRatio > 0.8)
              hashMap.put(set._1, 1)
          }
        }
      }
    }
    //printMap(hashMap)
  }

  //Percentage match
  def similarity(s1: String, s2: String): Double = {
    var longer = s1
    var shorter = s2
    if (s1.length < s2.length) { // longer should always have greater length
      longer = s2
      shorter = s1
    }
    val longerLength = longer.length
    if (longerLength == 0) return 1.0 /* both strings are zero length */
    (longerLength - editDistance(longer.toLowerCase, shorter.toLowerCase)) / longerLength.toDouble
  }

  //Levenshtein Edit Distance
  def editDistance(s1: String, s2: String): Int = {
    val costs = new Array[Int](s2.length + 1)
    var i = 0
    while ( {
      i <= s1.length
    }) {
      var lastValue = i
      var j = 0
      while ( {
        j <= s2.length
      }) {
        if (i == 0) costs(j) = j
        else if (j > 0) {
          var newValue = costs(j - 1)
          if (s1.charAt(i - 1) != s2.charAt(j - 1)) newValue = Math.min(Math.min(newValue, lastValue), costs(j)) + 1
          costs(j - 1) = lastValue
          lastValue = newValue
        }

        {
          j += 1
          j - 1
        }
      }
      if (i > 0) costs(s2.length) = lastValue

      {
        i += 1
        i - 1
      }
    }
    costs(s2.length)
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
    val lines = fromFile(value.replace("file:", ""))
    var itr = lines.getLines()
    itr.foreach {
      lib => {
        if (paymentsList.contains(lib.toLowerCase()))
          return true
      }
    }
    false
  }

  def checkForDangerousLibs(): Boolean = {
    var value = codeUri + "third_party_libs.txt"
    val lines = fromFile(value.replace("file:", ""))
    var itr = lines.getLines()
    itr.foreach {
      lib => {
        if (dangerousList.contains(lib.toLowerCase()))
          return true
      }
    }
    false
  }
}