package org.argus.feature_extractor.random

import java.io.PrintWriter
import java.util.regex.Pattern

import org.argus.amandroid.alir.componentSummary.ApkYard
import org.argus.amandroid.alir.pta.model.AndroidModelCallHandler
import org.argus.amandroid.alir.pta.reachingFactsAnalysis.{AndroidReachingFactsAnalysis, AndroidReachingFactsAnalysisConfig}
import org.argus.amandroid.alir.pta.summaryBasedAnalysis.AndroidSummaryProvider
import org.argus.amandroid.alir.taintAnalysis.{AndroidDataDependentTaintAnalysis, DataLeakageAndroidSourceAndSinkManager}
import org.argus.amandroid.core.decompile.{DecompileLayout, DecompileStrategy, DecompilerSettings}
import org.argus.amandroid.core.parser.IntentFilterDataBase
import org.argus.amandroid.core.{AndroidGlobalConfig, ApkGlobal}
import org.argus.feature_extractor._
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
  var outputUri: FileResourceUri = _
  var allCalls: MLinkedMap[String, Integer] = mutable.LinkedHashMap()
  var allAssets: MLinkedMap[String, Integer] = AllAssets.hashMap
  var allFeatures: MLinkedMap[String, Integer] = AllCustomFeatures.hashMap
  var resultUri: String = _

  @throws(classOf[Exception])
  def main(args: Array[String]): Unit = {
    if (args.length != 3) {
      println("Usage\nsourceFolder destFolder resultFolder")
      return
    }
    var folderUri = FileUtil.toUri(args(0))
    var paths = FileUtil.listFiles(folderUri, ".apk", recursive = false)

    if (paths.isEmpty) {
      println("No apks present in the specified folder")
      return
    }
    resultUri = args(2)
    try {
      paths.foreach {
        fileUri => {
          //REFRESH THE MAPS
          permMap = AllPermissions.hashMap
          recvMap = AllReceiver.hashMap
          dangerApis = DangerousCalls.hashMap
          allCalls = mutable.LinkedHashMap()
          allAssets = AllAssets.hashMap
          allFeatures = AllCustomFeatures.hashMap

          outputUri = FileUtil.toUri(args(1))
          val reporter = new DefaultReporter
          val yard = new ApkYard(reporter)
          val layout = DecompileLayout(outputUri)
          val strategy = DecompileStrategy(layout)
          val settings = DecompilerSettings(debugMode = true, forceDelete = true, strategy, reporter)
          apk = yard.loadApk(fileUri, settings, collectInfo = true, resolveCallBack = true)
          var name = apk.model.getAppName.replace(".apk", "")
          codeUri = outputUri + name + "/"
          codeUri.replace("file:", "")
          val components = apk.model.getComponents
          components.foreach {
            component => {
              apk.model.getEnvMap.get(component) match {
                case Some((esig, _)) =>
                  try {
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
                  } catch {
                    case e: Exception =>
                  }
                case None =>
              }
            }
          }

          val permissions = apk.model.getUsesPermissions
          val receivers = apk.model.getIntentFilterDB

          modAll(permissions)(permMap)
          modAllRecv(receivers)(recvMap)
          assetAnalyser()
          modDangerousCall(allCalls)(dangerApis)

          setCustomFeatures()
          /* METHOD_WISE CODE ANALYSIS */

          var isCheckingForEmulator = false
          var isCheckingInstalledApplications = false
          var isTryingToHide = false
          var isDeletinMessages = false
          var isURLAnIP = false

          val allMethods = apk.getApplicationClasses.map(c => c.getDeclaredMethods).reduce(_ ++ _)
          allMethods.foreach { m =>
            val code = m.retrieveCode.toString
            if (!isCheckingForEmulator)
              isCheckingForEmulator = checkForEmulator(code)
            if (!isCheckingInstalledApplications)
              isCheckingInstalledApplications = checkInstalledApplications(code)
            if (!isTryingToHide)
              isTryingToHide = checkHide(code)
            if (!isURLAnIP)
              isURLAnIP = checkURLForIp(code)
            if (!isDeletinMessages)
              isDeletinMessages = isDeletingMessages(code)
          }

          if (isCheckingForEmulator)
            allAssets.put("isCheckingForEmulator", 1)
          if (isCheckingInstalledApplications)
            allAssets.put("isCheckingForInstalledApplications", 1)
          if (isTryingToHide)
            allAssets.put("isTryingToHide", 1)
          if (isURLAnIP)
            allAssets.put("isDeletingMessages", 1)
          if (isDeletinMessages)
            allAssets.put("isURLAnIp", 1)

          mapSummer()
        }
      }
    } catch {
      case e: Exception =>
    }
  }

  @throws(classOf[Exception])
  def modDangerousCall(item: MLinkedMap[String, Integer])(hashMap: MLinkedMap[String, Integer]): Unit = {
    item.foreach {
      hello => {
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
  @throws(classOf[Exception])
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
  @throws(classOf[Exception])
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

  @throws(classOf[Exception])
  def setCustomFeatures(): Unit = {
    val isNumberPresent = numberFinder()
    val isPaymentSDKPresent = checkForPayment()
    val isDangerousLibPresent = checkForDangerousLibs()

    if (isNumberPresent)
      allFeatures.put("isNumberPresent", 1)
    if (isPaymentSDKPresent)
      allFeatures.put("isPaymentSDKUsed", 1)
    if (isDangerousLibPresent)
      allFeatures.put("isDangerousLibPresent", 1)
  }

  @throws(classOf[Exception])
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

  @throws(classOf[Exception])
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

  @throws(classOf[Exception])
  def assetAnalyser(): Unit = {
    val so_files = FileUtil.listFiles(codeUri, ".so", recursive = true)
    if (so_files.nonEmpty)
      allAssets.put(".so", 1)

    val lnk_file = FileUtil.listFiles(codeUri, ".lnk", recursive = true)
    if (lnk_file.nonEmpty)
      allAssets.put(".lnk", 1)

    val exe_file = FileUtil.listFiles(codeUri, ".exe", recursive = true)
    if (exe_file.nonEmpty)
      allAssets.put(".exe", 1)

    val zip_file = FileUtil.listFiles(codeUri, ".zip", recursive = true)
    if (zip_file.nonEmpty)
      allAssets.put(".zip", 1)

    val tar_file = FileUtil.listFiles(codeUri, ".tar", recursive = true)
    if (tar_file.nonEmpty)
      allAssets.put(".tar", 1)

    val rar_file = FileUtil.listFiles(codeUri, ".rar", recursive = true)
    if (rar_file.nonEmpty)
      allAssets.put(".rar", 1)

    val sevenz_file = FileUtil.listFiles(codeUri, ".7z", recursive = true)
    if (sevenz_file.nonEmpty)
      allAssets.put(".7z", 1)

    if (numberFinder())
      allAssets.put("hasContacts", 1)

    if (checkAllFilesType())
      allAssets.put("fakeExtension", 1)
  }

  // Number fetcher
  @throws(classOf[Exception])
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

  @throws(classOf[Exception])
  def checkAllFilesType(): Boolean = {
    try {
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
    } catch {
      case e: Exception =>
    }
    false
  }

  @throws(classOf[Exception])
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
  }

  @throws(classOf[Exception])
  def modAll(item: ISet[String])(hashMap: MLinkedMap[String, Integer]): Unit = {
    item.foreach {
      hello => {
        if (hashMap.contains(hello)) {
          hashMap.put(hello, 1)
        }
      }
    }
  }

  @throws(classOf[Exception])
  def checkURLForIp(code: String): Boolean = {
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

  @throws(classOf[Exception])
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

  @throws(classOf[Exception])
  def checkInstalledApplications(code: String): Boolean = {
    if (code.contains("getPackageManager") && code.contains("getInstalledApplications"))
      true
    else if (code.contains("getPackageManager") && code.contains("queryIntentActivities"))
      true
    else
      false
  }

  @throws(classOf[Exception])
  def checkHide(code: String): Boolean = {
    if (code.contains("getPackageManager") && code.contains("android.content.ComponentName") && code.contains("setComponentEnabledSetting"))
      true
    else
      false
  }

  @throws(classOf[Exception])
  def isDeletingMessages(code: String): Boolean = {
    if (code.contains("content://sms") && code.contains("getContentResolver") && code.contains("delete"))
      true
    else
      false
  }

  @throws(classOf[Exception])
  def mapSummer(): Unit = {
    var fullFeatures = permMap ++ recvMap ++ dangerApis ++ allAssets ++ allFeatures
    val writer = new PrintWriter(resultUri + apk.model.getAppName.replace(".apk", "") + ".txt", "UTF-8")
    fullFeatures.foreach {
      set =>
        writer.write(set.toString() + "\n")
    }
    writer.close()
    var code = "rm -rf " + codeUri.replace("file:", "")
    code.!
  }

  @throws(classOf[Exception])
  def printMap(hashMap: MLinkedMap[String, Integer]): Unit = {
    var set = hashMap.keySet
    set.foreach {
      hello => {
        println(hello + "     " + hashMap(hello))
      }
    }
  }
}