<?php
/**
 * SBOMImporter — parses CycloneDX SBOM files (JSON and XML) and
 * creates / updates iTop objects:
 *   SBOMArtifact, SBOMComponent,
 *   lnkSBOMArtifactToSBOMComponent, lnkSBOMComponentToSBOMComponent
 *
 * Usage:
 *   $oImporter = new SBOMImporter();
 *   $aResult   = $oImporter->ImportFromJSON($sJSON, $iOrgId, $iFunctionalCIId);
 *   $aResult   = $oImporter->ImportFromXML($sXML,  $iOrgId, $iFunctionalCIId);
 *
 * Both methods return an array:
 *   [
 *     'artifact_id'       => int,
 *     'artifact_name'     => string,
 *     'component_count'   => int,
 *     'dep_edge_count'    => int,
 *     'skipped_count'     => int,   // duplicate components reused
 *     'errors'            => [],
 *   ]
 */
class SBOMImporter
{
	/** @var array Human-readable errors collected during import */
	private $aErrors = array();

	// -------------------------------------------------------------------------
	// Public entry points
	// -------------------------------------------------------------------------

	/**
	 * Import from a CycloneDX JSON string.
	 *
	 * @param string $sJSON           Raw JSON content
	 * @param int    $iOrgId          iTop Organisation id
	 * @param int    $iFunctionalCIId iTop FunctionalCI id (0 = none)
	 * @return array
	 */
	public function ImportFromJSON($sJSON, $iOrgId, $iFunctionalCIId = 0)
	{
		$aData = json_decode($sJSON, true);
		if (json_last_error() !== JSON_ERROR_NONE) {
			throw new Exception('Invalid JSON: ' . json_last_error_msg());
		}
		if (($aData['bomFormat'] ?? '') !== 'CycloneDX') {
			throw new Exception('File does not appear to be a CycloneDX BOM (bomFormat field missing or wrong).');
		}

		return $this->ProcessData($aData, $iOrgId, $iFunctionalCIId);
	}

	/**
	 * Import from a CycloneDX XML string.
	 *
	 * @param string $sXML            Raw XML content
	 * @param int    $iOrgId          iTop Organisation id
	 * @param int    $iFunctionalCIId iTop FunctionalCI id (0 = none)
	 * @return array
	 */
	public function ImportFromXML($sXML, $iOrgId, $iFunctionalCIId = 0)
	{
		libxml_use_internal_errors(true);
		$oXML = simplexml_load_string($sXML);
		if ($oXML === false) {
			$sErrors = implode('; ', array_map(function ($e) { return $e->message; }, libxml_get_errors()));
			throw new Exception('Invalid XML: ' . $sErrors);
		}

		// Normalise to the same array shape used by the JSON path
		$aData = $this->NormaliseCycloneDXXML($oXML);
		return $this->ProcessData($aData, $iOrgId, $iFunctionalCIId);
	}

	// -------------------------------------------------------------------------
	// Core processing
	// -------------------------------------------------------------------------

	/**
	 * Process the normalised CycloneDX data array and create iTop objects.
	 */
	private function ProcessData(array $aData, $iOrgId, $iFunctionalCIId)
	{
		$this->aErrors = array();

		$sCycloneDXVersion = $aData['specVersion'] ?? '';
		$sSerialNumber     = $aData['serialNumber'] ?? '';
		$aMetadata         = $aData['metadata'] ?? array();
		$aMetaComponent    = $aMetadata['component'] ?? array();
		$aComponents       = $aData['components'] ?? array();
		$aDependencies     = $aData['dependencies'] ?? array();

		// ------------------------------------------------------------------
		// 1. Create / update the SBOMArtifact (primary component)
		// ------------------------------------------------------------------
		$oArtifact = $this->FindOrCreateArtifact(
			$aMetaComponent,
			$iOrgId,
			$iFunctionalCIId,
			$sCycloneDXVersion,
			$sSerialNumber,
			$aMetadata
		);
		$iArtifactId = $oArtifact->GetKey();

		// ------------------------------------------------------------------
		// 2. Create / update SBOMComponent objects (flat list)
		// ------------------------------------------------------------------
		// Map purl -> SBOMComponent id for linking
		$aPurlToComponentId = array();
		$iComponentCount    = 0;
		$iSkipped           = 0;

		// Also index the main artifact purl so dependency edges can reference it
		$sArtifactPurl = $aMetaComponent['purl'] ?? '';
		if ($sArtifactPurl !== '') {
			$aPurlToComponentId[$sArtifactPurl] = null; // placeholder — artifact is not a SBOMComponent
		}

		foreach ($aComponents as $aComp) {
			$sPurl = $aComp['purl'] ?? '';
			$sName = $aComp['name'] ?? 'unknown';

			// Try to reuse an existing SBOMComponent (reconcile on purl when available)
			$oComponent = null;
			if ($sPurl !== '') {
				$oComponent = $this->FindComponentByPurl($sPurl);
			}
			if ($oComponent === null) {
				$oComponent = MetaModel::NewObject('SBOMComponent');
				$iComponentCount++;
			} else {
				$iSkipped++;
			}

			$this->PopulateComponent($oComponent, $aComp, $iOrgId);
			if ($oComponent->IsNew()) {
				$oComponent->DBInsertNoReload();
			} else {
				$oComponent->DBUpdate();
			}

			$iCompId = $oComponent->GetKey();
			if ($sPurl !== '') {
				$aPurlToComponentId[$sPurl] = $iCompId;
			} else {
				// Fall back to name+version key for components without purl
				$aPurlToComponentId[$sName . '@' . ($aComp['version'] ?? '')] = $iCompId;
			}

			// Create link: artifact -> component (all as 'direct' initially;
			// transitive will be updated from the dependencies graph below)
			$this->EnsureArtifactComponentLink($iArtifactId, $iCompId, 'direct');
		}

		// ------------------------------------------------------------------
		// 3. Build component-to-component dependency edges
		// ------------------------------------------------------------------
		$iDepEdgeCount = 0;
		foreach ($aDependencies as $aDep) {
			$sRef      = $aDep['ref'] ?? '';
			$aDependsOn = $aDep['dependsOn'] ?? array();

			// Skip edges where the dependent is the primary artifact
			// (it's already linked to all components as an artifact)
			$iDependentCompId = $aPurlToComponentId[$sRef] ?? null;
			if ($iDependentCompId === null) {
				continue; // ref not found in our component map
			}

			foreach ($aDependsOn as $sDependencyPurl) {
				$iDependencyCompId = $aPurlToComponentId[$sDependencyPurl] ?? null;
				if ($iDependencyCompId === null) {
					continue;
				}
				$this->EnsureComponentDepEdge($iDependentCompId, $iDependencyCompId);
				$iDepEdgeCount++;

				// Mark this component as 'transitive' in the artifact link
				// if the dependent is itself not directly linked to the artifact
				// (i.e. it was pulled in by another component, not the artifact root).
				// Simplification: leave all links as 'direct' — the dep graph edges
				// carry the granular information.
			}
		}

		return array(
			'artifact_id'     => $iArtifactId,
			'artifact_name'   => $oArtifact->GetName(),
			'component_count' => $iComponentCount,
			'dep_edge_count'  => $iDepEdgeCount,
			'skipped_count'   => $iSkipped,
			'errors'          => $this->aErrors,
		);
	}

	// -------------------------------------------------------------------------
	// Object helpers
	// -------------------------------------------------------------------------

	private function FindOrCreateArtifact(
		array $aMetaComponent,
		$iOrgId,
		$iFunctionalCIId,
		$sCycloneDXVersion,
		$sSerialNumber,
		array $aMetadata
	) {
		$sName    = $aMetaComponent['name']    ?? 'Unknown SBOM Artifact';
		$sVersion = $aMetaComponent['version'] ?? '';
		$sPurl    = $aMetaComponent['purl']    ?? '';

		// Try to find an existing artifact by serial number first, then by name+version+org
		$oArtifact = null;
		if ($sSerialNumber !== '') {
			$oSet = new DBObjectSet(
				DBObjectSearch::FromOQL(
					"SELECT SBOMArtifact WHERE sbom_serial_number = :sn AND org_id = :org",
					array('sn' => $sSerialNumber, 'org' => $iOrgId)
				)
			);
			if ($oSet->Count() > 0) {
				$oArtifact = $oSet->Fetch();
			}
		}
		if ($oArtifact === null && $sName !== '') {
			$oSet = new DBObjectSet(
				DBObjectSearch::FromOQL(
					"SELECT SBOMArtifact WHERE name = :n AND version = :v AND org_id = :org",
					array('n' => $sName, 'v' => $sVersion, 'org' => $iOrgId)
				)
			);
			if ($oSet->Count() > 0) {
				$oArtifact = $oSet->Fetch();
			}
		}

		$bNew = ($oArtifact === null);
		if ($bNew) {
			$oArtifact = MetaModel::NewObject('SBOMArtifact');
		}

		$oArtifact->Set('name',               $sName);
		$oArtifact->Set('version',             $sVersion);
		$oArtifact->Set('purl',                $sPurl);
		$oArtifact->Set('org_id',              $iOrgId);
		$oArtifact->Set('cyclonedx_version',   $sCycloneDXVersion);
		$oArtifact->Set('sbom_serial_number',  $sSerialNumber);
		$oArtifact->Set('component_type',      $aMetaComponent['type'] ?? 'application');

		// Supplier from metadata.supplier or metadata.manufacture
		$sSupplier = $aMetadata['supplier']['name']    ??
		             $aMetadata['manufacture']['name']  ??
		             ($aMetaComponent['supplier']['name'] ?? '');
		if ($sSupplier !== '') {
			$oArtifact->Set('supplier_name', $sSupplier);
		}

		// License
		$sLicense = $this->ExtractLicense($aMetaComponent['licenses'] ?? array());
		if ($sLicense !== '') {
			$oArtifact->Set('license_expression', $sLicense);
		}

		// Link to FunctionalCI
		if ($iFunctionalCIId > 0) {
			$oArtifact->Set('functionalci_id', $iFunctionalCIId);
		}

		if ($bNew) {
			$oArtifact->DBInsertNoReload();
		} else {
			$oArtifact->DBUpdate();
		}

		return $oArtifact;
	}

	private function PopulateComponent(DBObject $oComponent, array $aComp, $iOrgId)
	{
		$oComponent->Set('name',               $aComp['name']    ?? 'unknown');
		$oComponent->Set('org_id',             $iOrgId);
		$oComponent->Set('version',            $aComp['version'] ?? '');
		$oComponent->Set('purl',               $aComp['purl']    ?? '');
		$oComponent->Set('cpe',                $aComp['cpe']     ?? '');
		$oComponent->Set('component_type',     $aComp['type']    ?? 'library');
		$oComponent->Set('supplier_name',      $aComp['supplier']['name'] ?? '');
		$oComponent->Set('description',        $aComp['description'] ?? '');

		$sLicense = $this->ExtractLicense($aComp['licenses'] ?? array());
		$oComponent->Set('license_expression', $sLicense);

		$sHash = $this->ExtractHash($aComp['hashes'] ?? array(), 'SHA-256');
		$oComponent->Set('hash_sha256', $sHash);
	}

	/** Return an existing SBOMComponent with this purl, or null */
	private function FindComponentByPurl($sPurl)
	{
		$oSet = new DBObjectSet(
			DBObjectSearch::FromOQL(
				"SELECT SBOMComponent WHERE purl = :purl",
				array('purl' => $sPurl)
			)
		);
		if ($oSet->Count() > 0) {
			return $oSet->Fetch();
		}
		return null;
	}

	/** Create an lnkSBOMArtifactToSBOMComponent row if it does not exist */
	private function EnsureArtifactComponentLink($iArtifactId, $iComponentId, $sDependencyType)
	{
		$oSet = new DBObjectSet(
			DBObjectSearch::FromOQL(
				"SELECT lnkSBOMArtifactToSBOMComponent WHERE artifact_id = :a AND component_id = :c",
				array('a' => $iArtifactId, 'c' => $iComponentId)
			)
		);
		if ($oSet->Count() > 0) {
			return; // already linked
		}
		$oLink = MetaModel::NewObject('lnkSBOMArtifactToSBOMComponent');
		$oLink->Set('artifact_id',      $iArtifactId);
		$oLink->Set('component_id',     $iComponentId);
		$oLink->Set('dependency_type',  $sDependencyType);
		$oLink->DBInsertNoReload();
	}

	/** Create an lnkSBOMComponentToSBOMComponent edge if it does not exist */
	private function EnsureComponentDepEdge($iDependentId, $iDependencyId)
	{
		$oSet = new DBObjectSet(
			DBObjectSearch::FromOQL(
				"SELECT lnkSBOMComponentToSBOMComponent WHERE dependent_id = :a AND dependency_id = :b",
				array('a' => $iDependentId, 'b' => $iDependencyId)
			)
		);
		if ($oSet->Count() > 0) {
			return;
		}
		$oLink = MetaModel::NewObject('lnkSBOMComponentToSBOMComponent');
		$oLink->Set('dependent_id',  $iDependentId);
		$oLink->Set('dependency_id', $iDependencyId);
		$oLink->DBInsertNoReload();
	}

	// -------------------------------------------------------------------------
	// Value extraction helpers
	// -------------------------------------------------------------------------

	/** Extract a combined SPDX expression from a CycloneDX licenses array */
	private function ExtractLicense(array $aLicenses)
	{
		$aParts = array();
		foreach ($aLicenses as $aLicEntry) {
			if (isset($aLicEntry['license']['id'])) {
				$aParts[] = $aLicEntry['license']['id'];
			} elseif (isset($aLicEntry['license']['name'])) {
				$aParts[] = $aLicEntry['license']['name'];
			} elseif (isset($aLicEntry['expression'])) {
				$aParts[] = $aLicEntry['expression'];
			}
		}
		return implode(' AND ', $aParts);
	}

	/** Extract a hash value by algorithm name from a CycloneDX hashes array */
	private function ExtractHash(array $aHashes, $sAlg)
	{
		foreach ($aHashes as $aHash) {
			if (($aHash['alg'] ?? '') === $sAlg) {
				return $aHash['content'] ?? '';
			}
		}
		return '';
	}

	// -------------------------------------------------------------------------
	// XML normalisation — converts SimpleXMLElement to the same array shape
	// as the JSON decoder so ProcessData() works for both formats.
	// -------------------------------------------------------------------------

	private function NormaliseCycloneDXXML(SimpleXMLElement $oXML)
	{
		// Register the default CycloneDX namespace
		$ns = $oXML->getNamespaces(true);
		$sNS = reset($ns) ?: 'http://cyclonedx.org/schema/bom/1.4';
		$oXML->registerXPathNamespace('cdx', $sNS);

		$aData = array(
			'bomFormat'   => 'CycloneDX',
			'specVersion' => (string)($oXML->attributes()['version'] ?? ''),
			'serialNumber'=> (string)($oXML->attributes()['serialNumber'] ?? ''),
			'metadata'    => array(),
			'components'  => array(),
			'dependencies'=> array(),
		);

		// metadata/component
		$aMetaComp = $oXML->xpath('cdx:metadata/cdx:component');
		if (!empty($aMetaComp)) {
			$aData['metadata']['component'] = $this->XMLComponentToArray($aMetaComp[0], $sNS);
		}

		// metadata/supplier
		$aSupplier = $oXML->xpath('cdx:metadata/cdx:supplier');
		if (!empty($aSupplier)) {
			$aData['metadata']['supplier'] = array('name' => (string)$aSupplier[0]->name);
		}

		// components
		foreach ($oXML->xpath('cdx:components/cdx:component') as $oComp) {
			$aData['components'][] = $this->XMLComponentToArray($oComp, $sNS);
		}

		// dependencies
		foreach ($oXML->xpath('cdx:dependencies/cdx:dependency') as $oDep) {
			$aDep = array(
				'ref'       => (string)$oDep->attributes()['ref'],
				'dependsOn' => array(),
			);
			foreach ($oDep->xpath('cdx:dependency') as $oSubDep) {
				$aDep['dependsOn'][] = (string)$oSubDep->attributes()['ref'];
			}
			$aData['dependencies'][] = $aDep;
		}

		return $aData;
	}

	private function XMLComponentToArray(SimpleXMLElement $oComp, $sNS)
	{
		$oComp->registerXPathNamespace('cdx', $sNS);
		$aComp = array(
			'type'        => (string)($oComp->attributes()['type'] ?? 'library'),
			'name'        => (string)$oComp->name,
			'version'     => (string)$oComp->version,
			'purl'        => (string)$oComp->purl,
			'cpe'         => (string)$oComp->cpe,
			'description' => (string)$oComp->description,
			'licenses'    => array(),
			'hashes'      => array(),
			'supplier'    => array('name' => ''),
		);

		// Supplier
		if (isset($oComp->supplier->name)) {
			$aComp['supplier']['name'] = (string)$oComp->supplier->name;
		}

		// Licenses
		foreach ($oComp->xpath('cdx:licenses/cdx:license') as $oLic) {
			$aComp['licenses'][] = array(
				'license' => array(
					'id'   => (string)$oLic->id,
					'name' => (string)$oLic->name,
				),
			);
		}
		foreach ($oComp->xpath('cdx:licenses/cdx:expression') as $oExpr) {
			$aComp['licenses'][] = array('expression' => (string)$oExpr);
		}

		// Hashes
		foreach ($oComp->xpath('cdx:hashes/cdx:hash') as $oHash) {
			$aComp['hashes'][] = array(
				'alg'     => (string)$oHash->attributes()['alg'],
				'content' => (string)$oHash,
			);
		}

		return $aComp;
	}
}
