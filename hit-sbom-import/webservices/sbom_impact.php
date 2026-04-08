<?php
/**
 * SBOM Impact Analysis page
 *
 * Renders iTop's impact/dependency graph starting from an SBOMComponent
 * or SBOMArtifact — without touching any iTop core file.
 *
 * This page clones the logic of pages/UI.php?operation=view_relations and
 * includes local copies of the two small helper functions (DisplayNavigatorListTab
 * and DisplayNavigatorGroupTab) that are otherwise defined inside UI.php.
 *
 * URL (once the extension is installed inside web/extensions/):
 *   https://<itop>/extensions/hit-sbom-import/webservices/sbom_impact.php
 *     ?class=SBOMComponent&id=<id>
 *
 * Optional parameters (identical to the core view_relations operation):
 *   relation=impacts      default: impacts
 *   direction=down        default: down  (use "up" for "depends on" direction)
 *   g=5                   grouping threshold, default: 5
 */

// ---------------------------------------------------------------------------
// Bootstrap iTop
// Path: itop/extensions/hit-sbom-import/webservices/ → 3 levels up = itop root
// ---------------------------------------------------------------------------
$sAppRoot = realpath(dirname(__FILE__) . '/../../..');
require_once($sAppRoot . '/approot.inc.php');
require_once(APPROOT . '/application/application.inc.php');
require_once(APPROOT . '/application/startup.inc.php');

// ---------------------------------------------------------------------------
// Authentication — same pattern as import_sbom.php
// ---------------------------------------------------------------------------
require_once(APPROOT . '/application/loginwebpage.class.inc.php');
$iRet = LoginWebPage::DoLogin(false, false, LoginWebPage::EXIT_RETURN);
if ($iRet != LoginWebPage::EXIT_CODE_OK) {
	LoginWebPage::DoLogin(); // Redirect browser to iTop login page
	exit;
}

// ---------------------------------------------------------------------------
// Parameters
// ---------------------------------------------------------------------------
$sClass     = utils::ReadParam('class',     'SBOMComponent', false, 'class');
$iId        = (int) utils::ReadParam('id',  0,               false, 'integer');
$sRelation  = utils::ReadParam('relation',  'impacts',        false, 'string');
$sDirection = utils::ReadParam('direction', 'down',           false, 'string');
$iGroupingThreshold = (int) utils::ReadParam('g', 5,          false, 'integer');

// ---------------------------------------------------------------------------
// Validate
// ---------------------------------------------------------------------------
if (!MetaModel::IsValidClass($sClass)) {
	throw new CoreException('Invalid class', array('class' => $sClass));
}

// ---------------------------------------------------------------------------
// No id — show a simple object-picker so the user can navigate here directly
// ---------------------------------------------------------------------------
if ($iId <= 0) {
	ShowPickerPage($sClass);
	exit;
}

// ---------------------------------------------------------------------------
// Build the relation graph (mirrors UI.php case 'view_relations')
// ---------------------------------------------------------------------------
require_once(APPROOT . 'core/simplegraph.class.inc.php');
require_once(APPROOT . 'core/relationgraph.class.inc.php');
require_once(APPROOT . 'core/displayablegraph.class.inc.php');

$oObj = MetaModel::GetObject($sClass, $iId);

// 'depends on' is an alias for impacts/up (same as core UI.php)
if ($sRelation === 'depends on') {
	$sRelation  = 'impacts';
	$sDirection = 'up';
}
$bDirDown = ($sDirection === 'down');

$iMaxRecursionDepth = MetaModel::GetConfig()->Get('relations_max_depth');
$aSourceObjects     = array($oObj);

if ($sDirection === 'up') {
	$oRelGraph = MetaModel::GetRelatedObjectsUp($sRelation, $aSourceObjects, $iMaxRecursionDepth);
} else {
	$oRelGraph = MetaModel::GetRelatedObjectsDown($sRelation, $aSourceObjects, $iMaxRecursionDepth);
}

$aResults      = $oRelGraph->GetObjectsByClass();
$oDisplayGraph = DisplayableGraph::FromRelationGraph($oRelGraph, $iGroupingThreshold, $bDirDown);

// ---------------------------------------------------------------------------
// Page setup
// ---------------------------------------------------------------------------
$sTitle        = MetaModel::GetRelationDescription($sRelation, $bDirDown) . ' ' . $oObj->GetName();
$sClassIcon    = MetaModel::GetClassIcon($sClass, false);
$oAppContext   = new ApplicationContext();

$oP = new iTopWebPage($sTitle);

// Breadcrumb
$sPageId      = 'sbom-impact-' . $sClass . '::' . $iId;
$sLabel       = $oObj->GetName() . ' ' . MetaModel::GetRelationLabel($sRelation, $bDirDown);
$sDescription = $sTitle;
$oP->SetBreadCrumbEntry($sPageId, $sLabel, $sDescription);

// ---------------------------------------------------------------------------
// Filter box + panel (identical to UI.php view_relations)
// ---------------------------------------------------------------------------
$sFirstTab   = MetaModel::GetConfig()->Get('impact_analysis_first_tab');
$bLazyLoad   = MetaModel::GetConfig()->Get('impact_analysis_lazy_loading');
$sContextKey = "hit-sbom-import/relation_context/$sClass/$sRelation/$sDirection";

// Attachment support (optional — same guard as core)
$sClassForAttachment = null;
$iIdForAttachment    = null;
if (class_exists('Attachment')) {
	$aAllowedClasses = MetaModel::GetModuleSetting('itop-attachments', 'allowed_classes', array('Ticket'));
	foreach ($aAllowedClasses as $sAllowedClass) {
		if ($oObj instanceof $sAllowedClass) {
			$sClassForAttachment = $sClass;
			$iIdForAttachment    = $iId;
		}
	}
}

$oP->AddSubBlock($oDisplayGraph->DisplayFilterBox($oP, $aResults, $bLazyLoad));

$oPanel = PanelUIBlockFactory::MakeForClass($sClass, $sTitle);
$oPanel->SetIcon($sClassIcon);
$oP->AddSubBlock($oPanel);
$oP->AddTabContainer('Navigator', '', $oPanel);
$oP->SetCurrentTabContainer('Navigator');

// Render tabs — graph first (default) or list first depending on config
if ($sFirstTab === 'list') {
	SBOMDisplayNavigatorListTab($oP, $aResults, $sRelation, $sDirection, $oObj);
	$oP->SetCurrentTab('UI:RelationshipGraph');
	$oDisplayGraph->DisplayGraph($oP, $sRelation, $oAppContext, array(), $sClassForAttachment, $iIdForAttachment, $sContextKey, array('this' => $oObj), $bLazyLoad);
	SBOMDisplayNavigatorGroupTab($oP);
} else {
	$oP->SetCurrentTab('UI:RelationshipGraph');
	$oDisplayGraph->DisplayGraph($oP, $sRelation, $oAppContext, array(), $sClassForAttachment, $iIdForAttachment, $sContextKey, array('this' => $oObj), $bLazyLoad);
	SBOMDisplayNavigatorListTab($oP, $aResults, $sRelation, $sDirection, $oObj);
	SBOMDisplayNavigatorGroupTab($oP);
}

$oP->SetCurrentTab('');
$oP->output();

// ---------------------------------------------------------------------------
// Local copies of the two small helpers from pages/UI.php
// Prefixed with SBOM_ to avoid any name collision if UI.php is included.
// ---------------------------------------------------------------------------

function SBOMDisplayNavigatorListTab($oP, $aResults, $sRelation, $sDirection, $oObj)
{
	$oP->SetCurrentTab('UI:RelationshipList');
	$oImpactedObject = UIContentBlockUIBlockFactory::MakeStandard('impacted_objects', array('ibo-is-visible'));
	$oP->AddSubBlock($oImpactedObject);
	$oImpactedObjectList = UIContentBlockUIBlockFactory::MakeStandard('impacted_objects_lists', array('ibo-is-visible'));
	$oImpactedObject->AddSubBlock($oImpactedObjectList);
	$oImpactedObjectList->AddSubBlock(
		UIContentBlockUIBlockFactory::MakeStandard('impacted_objects_lists_placeholder', array('ibo-is-visible'))
	);
}

function SBOMDisplayNavigatorGroupTab($oP)
{
	$oP->SetCurrentTab('UI:RelationGroups');
	$oP->add('<div id="impacted_groups">');
	$oP->add('<div id="impacted_groups_placeholder"></div>');
	// Content loaded asynchronously via pages/ajax.render.php?operation=relation_groups
	$oP->add('</div>');
}

// ---------------------------------------------------------------------------
// Object picker (shown when no id is given in the URL)
// ---------------------------------------------------------------------------
function ShowPickerPage(string $sClass): void
{
	$oP = new iTopWebPage(Dict::S('UI:SBOM:ImpactAnalysis'));
	$oP->add('<div class="page_header">');
	$oP->add('<h1><i class="fas fa-project-diagram"></i> ' . Dict::S('UI:SBOM:ImpactAnalysis') . '</h1>');
	$oP->add('</div>');

	$oP->add('<div class="wizContainer" style="max-width:540px;">');
	$oP->add('<p>' . Dict::S('UI:SBOM:ImpactSelectHelp') . '</p>');

	$sPageUrl = utils::GetAbsoluteUrlAppRoot()
		. 'extensions/hit-sbom-import/webservices/sbom_impact.php';

	$oP->add('<form method="get" action="' . htmlentities($sPageUrl) . '">');
	$oP->add('<table>');

	// Class selector
	$oP->add('<tr>');
	$oP->add('<td><label for="impact_class"><strong>' . Dict::S('UI:SBOM:ImpactClass') . ':</strong></label></td>');
	$oP->add('<td><select name="class" id="impact_class" class="multiselect">');
	foreach (array('SBOMComponent', 'SBOMArtifact') as $sCls) {
		$sSelected = ($sCls === $sClass) ? ' selected="selected"' : '';
		$oP->add('<option value="' . $sCls . '"' . $sSelected . '>'
			. MetaModel::GetName($sCls) . '</option>');
	}
	$oP->add('</select></td>');
	$oP->add('</tr>');

	// Object id
	$oP->add('<tr>');
	$oP->add('<td><label for="impact_id"><strong>' . Dict::S('UI:SBOM:ImpactObjectId') . ':</strong></label></td>');
	$oP->add('<td><input type="number" name="id" id="impact_id" min="1" value="" required style="width:120px;"></td>');
	$oP->add('</tr>');

	// Direction
	$oP->add('<tr>');
	$oP->add('<td><label for="impact_dir"><strong>' . Dict::S('UI:SBOM:ImpactDirection') . ':</strong></label></td>');
	$oP->add('<td><select name="direction" id="impact_dir" class="multiselect">');
	$oP->add('<option value="down">' . Dict::S('UI:SBOM:ImpactDirection:Down') . '</option>');
	$oP->add('<option value="up">' . Dict::S('UI:SBOM:ImpactDirection:Up') . '</option>');
	$oP->add('</select></td>');
	$oP->add('</tr>');

	$oP->add('</table>');
	$oP->add('<input type="hidden" name="relation" value="impacts">');
	$oP->add('<p>');
	$oP->add('<button type="submit" class="action"><span>' . Dict::S('UI:SBOM:ImpactShow') . '</span></button>');
	$oP->add('</p>');
	$oP->add('</form>');

	// Quick links to SBOM lists
	$sCompListUrl = utils::GetAbsoluteUrlAppRoot() . 'pages/UI.php?operation=search_form&class=SBOMComponent';
	$sArtListUrl  = utils::GetAbsoluteUrlAppRoot() . 'pages/UI.php?operation=search_form&class=SBOMArtifact';
	$oP->add('<p>');
	$oP->add('<a href="' . $sCompListUrl . '">' . Dict::S('Class:SBOMComponent') . ' list</a>');
	$oP->add(' &nbsp;|&nbsp; ');
	$oP->add('<a href="' . $sArtListUrl . '">' . Dict::S('Class:SBOMArtifact') . ' list</a>');
	$oP->add('</p>');
	$oP->add('</div>');

	$oP->output();
}
