<?php
/**
 * CycloneDX SBOM Import page
 *
 * URL (once the extension is installed inside web/extensions/):
 *   https://<itop>/extensions/hit-sbom-import/webservices/import_sbom.php
 *
 * The page bootstraps iTop, checks user authentication, then either
 * renders the upload form (GET) or processes the uploaded file (POST).
 *
 * Supported formats: CycloneDX JSON (.json) and CycloneDX XML (.xml)
 */

// ---------------------------------------------------------------------------
// Bootstrap iTop
// Path: itop/extensions/hit-sbom-import/webservices/ → 3 levels up = itop root
// ---------------------------------------------------------------------------
$sAppRoot = realpath(dirname(__FILE__) . '/../../..');
require_once($sAppRoot . '/approot.inc.php');
require_once(APPROOT . '/application/application.inc.php');
require_once(APPROOT . '/application/startup.inc.php');

// Include the importer class from the extension's lib folder
require_once(dirname(__FILE__) . '/../lib/SBOMImporter.php');

// ---------------------------------------------------------------------------
// Authentication — supports HTTP Basic Auth (for curl/API) and session login
// ---------------------------------------------------------------------------
$bIsApiCall = isset($_SERVER['HTTP_ACCEPT']) && strpos($_SERVER['HTTP_ACCEPT'], 'text/html') === false
           || isset($_SERVER['HTTP_X_REQUESTED_WITH']);

// Authentication — mirrors how iTop's own rest.php handles it
require_once(APPROOT . '/application/loginwebpage.class.inc.php');
$iRet = LoginWebPage::DoLogin(false, false, LoginWebPage::EXIT_RETURN);
if ($iRet != LoginWebPage::EXIT_CODE_OK) {
	header('WWW-Authenticate: Basic realm="iTop SBOM API"');
	header('Content-Type: application/json');
	http_response_code(401);
	echo json_encode(['status' => 'error', 'error' => 'Authentication required (HTTP Basic Auth)']);
	exit;
}

// ---------------------------------------------------------------------------
// Detect API (curl/non-browser) call: no Accept: text/html header
// ---------------------------------------------------------------------------
$bApiMode = !(isset($_SERVER['HTTP_ACCEPT']) && strpos($_SERVER['HTTP_ACCEPT'], 'text/html') !== false);

// Only create the iTop web page for browser requests (it touches output buffers)
$oP = null;
if (!$bApiMode) {
	$oP = new iTopWebPage(Dict::S('UI:SBOM:ImportTitle'));
}

// ---------------------------------------------------------------------------
// Handle POST (file upload + import)
// ---------------------------------------------------------------------------

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

	$iOrgId          = (int) ($_POST['org_id'] ?? utils::ReadPostedParam('org_id', 0, 'integer'));
	$iFunctionalCIId = (int) ($_POST['functionalci_id'] ?? utils::ReadPostedParam('functionalci_id', 0, 'integer'));

	if ($iOrgId === 0) {
		if ($bApiMode) { JsonError(400, 'org_id is required'); }
		$oP->add('<div class="alert alert-danger">' . Dict::S('UI:SBOM:Error:OrgRequired') . '</div>');
	} elseif (!isset($_FILES['sbom_file']) || $_FILES['sbom_file']['error'] !== UPLOAD_ERR_OK) {
		if ($bApiMode) { JsonError(400, 'sbom_file upload missing or failed (error code: ' . ($_FILES['sbom_file']['error'] ?? 'none') . ')'); }
		$oP->add('<div class="alert alert-danger">' . Dict::S('UI:SBOM:Error:FileRequired') . '</div>');
	} else {
		$sFileName = $_FILES['sbom_file']['name'];
		$sTmpPath  = $_FILES['sbom_file']['tmp_name'];
		$sContent  = file_get_contents($sTmpPath);
		$sExt      = strtolower(pathinfo($sFileName, PATHINFO_EXTENSION));

		try {
			$oImporter = new SBOMImporter();

			if ($sExt === 'json') {
				$aResult = $oImporter->ImportFromJSON($sContent, $iOrgId, $iFunctionalCIId);
			} elseif ($sExt === 'xml') {
				$aResult = $oImporter->ImportFromXML($sContent, $iOrgId, $iFunctionalCIId);
			} else {
				throw new Exception('Unsupported format: ' . $sExt . '. Use .json or .xml');
			}

			if ($bApiMode) {
				header('Content-Type: application/json');
				http_response_code(200);
				echo json_encode(['status' => 'ok'] + $aResult);
				exit;
			}

			// HTML success summary
			$sArtifactLink = utils::GetAbsoluteUrlAppRoot()
				. 'pages/UI.php?operation=details&class=SBOMArtifact&id=' . $aResult['artifact_id'];

			$oP->add('<div class="alert alert-success">');
			$oP->add('<h4>' . Dict::S('UI:SBOM:ImportSuccess') . '</h4>');
			$oP->add('<ul>');
			$oP->add('<li><strong>' . Dict::S('UI:SBOM:Artifact') . ':</strong> '
				. '<a href="' . $sArtifactLink . '">' . htmlentities($aResult['artifact_name']) . '</a></li>');
			$oP->add('<li><strong>' . Dict::S('UI:SBOM:ComponentsCreated') . ':</strong> '
				. (int)$aResult['component_count'] . '</li>');
			$oP->add('<li><strong>' . Dict::S('UI:SBOM:ComponentsReused') . ':</strong> '
				. (int)$aResult['skipped_count'] . '</li>');
			$oP->add('<li><strong>' . Dict::S('UI:SBOM:DepEdges') . ':</strong> '
				. (int)$aResult['dep_edge_count'] . '</li>');
			$oP->add('</ul>');

			if (!empty($aResult['errors'])) {
				$oP->add('<p><strong>' . Dict::S('UI:SBOM:Warnings') . ':</strong></p><ul>');
				foreach ($aResult['errors'] as $sErr) {
					$oP->add('<li>' . htmlentities($sErr) . '</li>');
				}
				$oP->add('</ul>');
			}
			$oP->add('</div>');

		} catch (Exception $e) {
			if ($bApiMode) { JsonError(500, $e->getMessage()); }
			$oP->add('<div class="alert alert-danger"><strong>'
				. Dict::S('UI:SBOM:Error:ImportFailed')
				. '</strong> ' . htmlentities($e->getMessage()) . '</div>');
		}
	}

	// Always show the form again after a POST so the user can import another file
	if (!$bApiMode) { RenderImportForm($oP, $iOrgId, $iFunctionalCIId); }

} else {
	// ---------------------------------------------------------------------------
	// Handle GET — render the empty form
	// ---------------------------------------------------------------------------
	RenderImportForm($oP, 0, 0);
}

if ($oP !== null) { $oP->output(); }

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function JsonError(int $iCode, string $sMessage): void
{
	header('Content-Type: application/json');
	http_response_code($iCode);
	echo json_encode(['status' => 'error', 'error' => $sMessage]);
	exit;
}

// ---------------------------------------------------------------------------
// Form renderer
// ---------------------------------------------------------------------------

/**
 * Renders the SBOM import form.
 *
 * @param WebPage $oP
 * @param int     $iOrgId          Pre-selected organisation id
 * @param int     $iFunctionalCIId Pre-selected FunctionalCI id
 */
function RenderImportForm(WebPage $oP, $iOrgId, $iFunctionalCIId)
{
	$sTransactionId = utils::GetNewTransactionId();

	$oP->add('<div class="page_header">');
	$oP->add('<h1><i class="fas fa-file-import"></i> ' . Dict::S('UI:SBOM:ImportTitle') . '</h1>');
	$oP->add('</div>');

	$oP->add('<div class="wizContainer" style="max-width:700px;">');
	$oP->add('<form method="post" enctype="multipart/form-data" id="sbom_import_form">');
	$oP->add('<input type="hidden" name="transaction_id" value="' . htmlentities($sTransactionId) . '">');

	// --- Organisation selector ---
	$oP->add('<fieldset>');
	$oP->add('<legend>' . Dict::S('UI:SBOM:Form:Step1') . '</legend>');
	$oP->add('<table>');

	// Organisation
	$oP->add('<tr>');
	$oP->add('<td><label for="org_id"><strong>' . Dict::S('Class:Organisation') . ' *</strong></label></td>');
	$oP->add('<td>');
	$oOrgSearch = DBObjectSearch::FromOQL('SELECT Organization');
	$oOrgSet    = new DBObjectSet($oOrgSearch);
	$oP->add('<select name="org_id" id="org_id" class="multiselect">');
	$oP->add('<option value="0">-- ' . Dict::S('UI:SelectOne') . ' --</option>');
	while ($oOrg = $oOrgSet->Fetch()) {
		$sSelected = ($oOrg->GetKey() === $iOrgId) ? ' selected="selected"' : '';
		$oP->add('<option value="' . $oOrg->GetKey() . '"' . $sSelected . '>'
			. htmlentities($oOrg->GetName()) . '</option>');
	}
	$oP->add('</select>');
	$oP->add('</td>');
	$oP->add('</tr>');

	// FunctionalCI (optional)
	$oP->add('<tr>');
	$oP->add('<td><label for="functionalci_id"><strong>' . Dict::S('Class:FunctionalCI') . '</strong></label></td>');
	$oP->add('<td>');
	$oFCISearch = DBObjectSearch::FromOQL('SELECT FunctionalCI ORDER BY name ASC');
	$oFCISet    = new DBObjectSet($oFCISearch);
	$oP->add('<select name="functionalci_id" id="functionalci_id" class="multiselect">');
	$oP->add('<option value="0">-- ' . Dict::S('UI:None') . ' --</option>');
	while ($oCI = $oFCISet->Fetch()) {
		$sSelected = ($oCI->GetKey() === $iFunctionalCIId) ? ' selected="selected"' : '';
		$oP->add('<option value="' . $oCI->GetKey() . '"' . $sSelected . '>'
			. htmlentities($oCI->GetName()) . ' (' . get_class($oCI) . ')</option>');
	}
	$oP->add('</select>');
	$oP->add('<br><small>' . Dict::S('UI:SBOM:Form:FunctionalCIHelp') . '</small>');
	$oP->add('</td>');
	$oP->add('</tr>');

	$oP->add('</table>');
	$oP->add('</fieldset>');

	// --- File upload ---
	$oP->add('<fieldset>');
	$oP->add('<legend>' . Dict::S('UI:SBOM:Form:Step2') . '</legend>');
	$oP->add('<p>' . Dict::S('UI:SBOM:Form:FileHelp') . '</p>');
	$oP->add('<input type="file" name="sbom_file" id="sbom_file" accept=".json,.xml" required>');
	$oP->add('</fieldset>');

	// --- Submit ---
	$oP->add('<p>');
	$oP->add('<button type="submit" class="action"><span>' . Dict::S('UI:SBOM:Form:Submit') . '</span></button>');
	$oP->add('</p>');

	$oP->add('</form>');
	$oP->add('</div>');

	// Add a "back to SBOM artifacts list" link
	$sListUrl = utils::GetAbsoluteUrlAppRoot()
		. 'pages/UI.php?operation=search_form&class=SBOMArtifact';
	$oP->add('<p><a href="' . $sListUrl . '">&#8592; ' . Dict::S('UI:SBOM:BackToList') . '</a></p>');
}
