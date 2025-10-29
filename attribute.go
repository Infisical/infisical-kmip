package kmip

/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

import (
	"time"
)

// Attribute is a Attribute Object Structure
type Attribute struct {
	Tag `kmip:"ATTRIBUTE"`

	Name  string      `kmip:"ATTRIBUTE_NAME"`
	Index int32       `kmip:"ATTRIBUTE_INDEX"`
	Value interface{} `kmip:"ATTRIBUTE_VALUE"`
}

// BuildFieldValue builds dynamic Value field
func (a *Attribute) BuildFieldValue(name string) (v interface{}, err error) {
	switch a.Name {
	case ATTRIBUTE_NAME_CRYPTOGRAPHIC_ALGORITHM:
		v = Enum(0)
	case ATTRIBUTE_NAME_CRYPTOGRAPHIC_LENGTH, ATTRIBUTE_NAME_CRYPTOGRAPHIC_USAGE_MASK, ATTRIBUTE_NAME_ACTIVATION_DATE, ATTRIBUTE_NAME_DEACTIVATION_DATE:
		v = int32(0)
	case ATTRIBUTE_NAME_UNIQUE_IDENTIFIER, ATTRIBUTE_NAME_OPERATION_POLICY_NAME:
		v = ""
	case ATTRIBUTE_NAME_OBJECT_TYPE, ATTRIBUTE_NAME_STATE:
		v = Enum(0)
	case ATTRIBUTE_NAME_INITIAL_DATE, ATTRIBUTE_NAME_LAST_CHANGE_DATE:
		v = time.Time{}
	case ATTRIBUTE_NAME_NAME:
		v = &Name{}
	case ATTRIBUTE_NAME_DIGEST:
		v = &Digest{}
	case ATTRIBUTE_NAME_CUSTOM_ATTRIBUTE:
		// Custom attributes can have any data type - return CustomAttribute structure
		v = &CustomAttribute{}
	default:
		// For unsupported attributes (including custom x- attributes and KMIP attributes we don't explicitly handle),
		// default to string type. The decoder will gracefully skip attributes with type mismatches
		// (e.g., structured attributes that we don't support), allowing decoding to continue.
		v = ""
	}

	return
}

// Attributes is a sequence of Attribute objects which allows building and search
type Attributes []Attribute

func (attrs Attributes) Get(name string) (val interface{}) {
	for i := range attrs {
		if attrs[i].Name == name {
			val = attrs[i].Value
			break
		}
	}

	return
}

// TemplateAttribute is a Template-Attribute Object Structure
type TemplateAttribute struct {
	Tag `kmip:"TEMPLATE_ATTRIBUTE"`

	Name       Name       `kmip:"NAME"`
	Attributes Attributes `kmip:"ATTRIBUTE"`
}

// Name is a Name Attribute Structure
type Name struct {
	Tag `kmip:"NAME"`

	Value string `kmip:"NAME_VALUE,required"`
	Type  Enum   `kmip:"NAME_TYPE,required"`
}

// Digest is a Digest Attribute Structure
type Digest struct {
	Tag `kmip:"DIGEST"`

	HashingAlgorithm Enum   `kmip:"HASHING_ALGORITHM,required"`
	DigestValue      []byte `kmip:"DIGEST_VALUE"`
	KeyFormatType    Enum   `kmip:"KEY_FORMAT_TYPE"`
}

// CustomAttribute is a Custom Attribute Structure
type CustomAttribute struct {
	Tag `kmip:"CUSTOM_ATTRIBUTE"`

	AttributeName  string      `kmip:"ATTRIBUTE_NAME,required"`
	AttributeValue interface{} `kmip:"ATTRIBUTE_VALUE,required"`
}

// BuildFieldValue builds dynamic Value field for CustomAttribute
func (ca *CustomAttribute) BuildFieldValue(name string) (v interface{}, err error) {
	switch name {
	case "AttributeValue":
		v = ""
	}
	return
}

type ApplicationSpecificInformation struct {
	Tag `kmip:"APPLICATION_SPECIFIC_INFORMATION"`

	ApplicationNamespace string `kmip:"APPLICATION_NAMESPACE,required"`
	ApplicationData      string `kmip:"APPLICATION_DATA,required"`
}

type Link struct {
	Tag `kmip:"LINK"`

	LinkType               Enum   `kmip:"LINK_TYPE,required"`
	LinkedObjectIdentifier string `kmip:"LINKED_OBJECT_IDENTIFIER,required"`
}

// ContactInformation is a Contact Information Attribute Structure
type ContactInformation struct {
	Tag `kmip:"CONTACT_INFORMATION"`

	ContactInformation string `kmip:"CONTACT_INFORMATION,required"`
}
