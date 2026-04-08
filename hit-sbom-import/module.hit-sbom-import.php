<?php
//
// iTop module definition file
//

SetupWebPage::AddModule(
	__FILE__, // Path to the current file, all other file names are relative to the directory containing this file
	'hit-sbom-import/1.0.0',
	array(
		// Identification
		'label' => 'SBOM Import (CycloneDX)',
		'category' => 'business',

		// Setup
		'dependencies' => array(
			'itop-config-mgmt/2.0.0',
		),
		'mandatory' => false,
		'visible' => true,

		// Components
		'datamodel' => array(
			'model.hit-sbom-import.php',
		),
		'webservice' => array(
		),
		'data.struct' => array(
		),
		'data.sample' => array(
		),

		// Documentation
		'doc.manual_setup' => '',
		'doc.more_information' => '',

		// Default settings
		'settings' => array(
		),
	)
);
