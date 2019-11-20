<?php
namespace Psecio\Versionscan\Command;

use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Input\InputOption;

class MissingCommand extends Command
{
    const CACHE_PATH = './tmp/';
    const CVE_START_YEAR = 2002;
    private $excludeCve = [];
    private $verbose = false;
    private $checksFilePath;
    private $output;
    private $cveDatabase;

    protected function configure()
    {
        $this->setName('missing')
            ->setDescription('Find vulnerabilities missing from current checks')
            ->setDefinition(array(
                new InputOption('save-results', 'save-results', InputOption::VALUE_OPTIONAL, 'Save missing vulnerabilities to the checks list'),
            ))
            ->setHelp(
                'Find vulnerabilities missing from current checks'
            );
    }

    /**
     * Execute the "missing" command
     *
     * @param  InputInterface $input Input object
     * @param  OutputInterface $output Output object
     */
    protected function execute(InputInterface $input, OutputInterface $output)
    {
        ini_set('memory_limit', '1000000000');
        $this->verbose = $input->getOption('verbose');
        $this->checksFilePath = __DIR__ . '/../../../Psecio/Versionscan/checks.json';
        $saveResults = $input->getOption('save-results');
        $this->output = $output;

        // This CVE appears in the changelog but was never officially recognized
        $this->excludeCve['CVE-2014-3622'] = true;

        // Load the CVE database
        $this->downloadCveDetails();
        $this->cveDatabase = $this->loadAllCveDetails();

        // Get our current checks
        $checksFileContents = json_decode(file_get_contents($this->checksFilePath), true);
        foreach ($checksFileContents['checks'] as $check) {
            $this->addCheckToCveDatabase($check);
        }

        $this->parseChangeLog(file_get_contents('https://www.php.net/ChangeLog-4.php'));
        $this->parseChangeLog(file_get_contents('https://www.php.net/ChangeLog-5.php'));
        $this->parseChangeLog(file_get_contents('https://www.php.net/ChangeLog-7.php'));


        if ($saveResults !== false) {
            $this->saveResults(array_values($this->cveDatabase));
        }
    }

    private function parseChangeLog($changelog)
    {
        // Parse the changelog into versions
        preg_match_all('#<section class="version" id="([0-9\.]+)">(.+?)</section>#ms', $changelog, $matches);

        foreach ($matches[0] as $index => $match) {
            $versionId = $matches[1][$index];

            // see if we have any CVEs
            if (strstr($match, 'CVE') === false) {
                continue;
            }

            // Extract our CVEs
            preg_match_all('/CVE-[0-9]+-[0-9]+/i', $match, $cveList);
            $cveList[0] = array_slice($cveList[0], 0, 1);

            foreach ($cveList[0] as $cveId) {
                $cveId = strtoupper($cveId);
                if (isset($this->excludeCve[$cveId])) {
                    // ignore this one
                    continue;
                }
                $cveDetail = $this->getOrCreateCveDetail($cveId);
                if (!in_array($versionId, $cveDetail['fixVersions']['base'])) {
                    $this->logMessage('Found new ', $cveId, ' fixed in ', $versionId);
                    $cveDetail['fixVersions']['base'][] = $versionId;
                } else {
                    $this->logDebugMessage('Found existing ', $cveId, ' fixed in ', $versionId);
                }
                $this->cveDatabase[$cveId] = $cveDetail;
            }
        }
    }

    private function addCheckToCveDatabase($check)
    {
        $cveId = $check['cveid'];
        $cveDetail = $this->getOrCreateCveDetail($cveId);
        $cveDetail['fixVersions'] = $check['fixVersions'];
        $this->cveDatabase[$cveId] = $cveDetail;
    }

    private function downloadCveDetails()
    {
        $currentYear = date("Y");
        for($cveYear = self::CVE_START_YEAR; $cveYear <= $currentYear; $cveYear++) {
            $fileName = $cveYear.'-cves.json';
            if (is_file(self::CACHE_PATH . $fileName)) {
                $this->logDebugMessage('Using cached CVEs for ' . $cveYear);
                continue;
            }
            $this->logMessage('Downloading CVEs for ' . $cveYear);
            $compressedDetails = gzopen('https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-'.$cveYear.'.json.gz', 'rb');
            if ($compressedDetails !== false) {
                file_put_contents(self::CACHE_PATH.$fileName, $compressedDetails);
            }
        }
    }

    private function loadAllCveDetails()
    {
        $currentYear = date("Y");
        $allCves = [];
        for($cveYear = self::CVE_START_YEAR; $cveYear <= $currentYear; $cveYear++) {
            $allCves = array_replace($allCves, $this->loadCveDetails($cveYear));
            $this->logMessage(sizeof($allCves), ' CVEs loaded');
        }
        return $allCves;
    }

    private function loadCveDetails($year)
    {
        $this->logDebugMessage('Loading CVEs for ', $year);
        $cveDetails = [];
        $string = file_get_contents(self::CACHE_PATH.$year.'-cves.json');
        if ($string === false) {
            $this->logMessage('Unable to find CVEs list for ', $year);
            return;
        }

        $json_a = json_decode($string, true);
        if ($json_a === null) {
            $this->logMessage('Unable to read CVEs list for ', $year);
            return;
        }

        foreach ($json_a['CVE_Items'] as $cve) {
            $parsedCve = $this->formatCveDetail($cve);
            $cveDetails[$parsedCve['cveid']] = $parsedCve;
        }
        return $cveDetails;
    }

    private function formatCveDetail($cveDetail)
    {
        $id = strtoupper(trim($cveDetail['cve']['CVE_data_meta']['ID']));
        $publishedDate = date_create_from_format('Y-m-d\TH:i\Z', $cveDetail['publishedDate'])
            ->format(\DateTime::ISO8601);
        $lastModifiedDate = date_create_from_format('Y-m-d\TH:i\Z', $cveDetail['lastModifiedDate'])
            ->format(\DateTime::ISO8601);

        // Get summary
        $summary = null;
        if (isset($cveDetail['cve']['description']['description_data'])) {
            foreach ($cveDetail['cve']['description']['description_data'] as $description) {
                if ($description['lang'] == 'en') {
                    $summary = $description['value'];
                    break;
                }
            }
        }

        // Get threat score
        $threat = null;
        if (isset($cveDetail['impact']['baseMetricV3'])) {
            $threat = $cveDetail['impact']['baseMetricV3']['cvssV3']['baseScore'];
        } else if (isset($cveDetail['impact']['baseMetricV2'])) {
            $threat = $cveDetail['impact']['baseMetricV2']['cvssV2']['baseScore'];
        }

        $cveDetail = $this->getOrCreateCveDetail($id);
        $cveDetail['threat'] = floatval($threat);
        $cveDetail['summary'] = $summary;
        $cveDetail['lastModifiedDate'] = $lastModifiedDate;
        $cveDetail['publishedDate'] = $publishedDate;

        return $cveDetail;
    }

    private function getOrCreateCveDetail($cveId)
    {
        // Set default values
        $cveDetail = [
            'cveid' => $cveId,
            'threat' => null,
            'summary' => null,
            'lastModifiedDate' => null,
            'publishedDate' => null,
            'fixVersions' => ['base' => []]
        ];
        if (isset($this->cveDatabase[$cveId])) {
            $cveDetail = array_replace($cveDetail, $this->cveDatabase[$cveId]);
        }
        return $cveDetail;
    }

    private function saveResults($results)
    {
        $checks = array_filter($results, function($cve) {
            // Only save CVEs that have fixed versions - this filters out all non-PHP related CVEs
            return isset($cve['fixVersions']['base']) && sizeof($cve['fixVersions']['base']) > 0;
        });

        // Sort checks by cveid
        usort($checks, function($row1, $row2) {
            $row1Parts = explode('-', $row1['cveid']);
            $row2Parts = explode('-', $row2['cveid']);
            if ($row1Parts[1] != $row2Parts[1]) {
                return strnatcmp($row1Parts[1], $row2Parts[1]);
            }
            return strnatcmp($row1Parts[2], $row2Parts[2]);
        });

        // Sort fix versions within each check
        foreach ($checks as $index => $check) {
            $versions = array_unique($checks[$index]['fixVersions']['base']);
            sort($versions);
            $checks[$index]['fixVersions']['base'] = $versions;
        }

        $allResults = [
            'checks' => $checks,
            'updatedAt' => Date('c')
        ];

        $json_data = json_encode($allResults, JSON_PRETTY_PRINT);
        file_put_contents($this->checksFilePath, $json_data);
    }

    private function logMessage()
    {
        $arg_list = func_get_args();
        foreach ($arg_list as $arg) {
            if (is_string($arg)) {
                $this->output->write($arg);
            } else {
                $message_object = json_encode($arg, JSON_PRETTY_PRINT);
                $message_object = trim(preg_replace('/\s+/', ' ', $message_object));
                $this->output->write($message_object);
            }
        }
        $this->output->write("\n");
    }

    private function logDebugMessage()
    {
        if ($this->verbose) {
            call_user_func_array(array($this, "logMessage"), func_get_args());
        }
    }
}
