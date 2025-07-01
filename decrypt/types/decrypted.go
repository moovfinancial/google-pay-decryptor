// Copyright (c) 2022 Rakhat

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package types

type Decrypted struct {
	GatewayMerchantId    string               `json:"gatewayMerchantId,omitempty"`
	MessageExpiration    string               `json:"messageExpiration"`
	MessageId            string               `json:"messageId"`
	PaymentMethod        string               `json:"paymentMethod"`
	PaymentMethodDetails PaymentMethodDetails `json:"paymentMethodDetails"`
}

type PaymentMethodDetails struct {
	AssuranceDetails *AssuranceDetails `json:"assuranceDetails,omitempty"`
	BillingAddress   *Address          `json:"billingAddress,omitempty"`
	CardDetails      string            `json:"cardDetails,omitempty"`
	CardNetwork      string            `json:"cardNetwork,omitempty"`
	Pan              string            `json:"pan,omitempty"`
	Dpan             string            `json:"dpan,omitempty"`
	ExpirationMonth  int               `json:"expirationMonth"`
	ExpirationYear   int               `json:"expirationYear"`
	AuthMethod       string            `json:"authMethod"`
	Cryptogram       string            `json:"cryptogram,omitempty"`
	EciIndicator     string            `json:"eciIndicator,omitempty"`
}

type AssuranceDetails struct {
	AccountVerified         bool `json:"accountVerified,omitempty"`
	CardHolderAuthenticated bool `json:"cardHolderAuthenticated"`
}

type Address struct {
	Name               string `json:"name,omitempty"`
	PostalCode         string `json:"postalCode,omitempty"`
	CountryCode        string `json:"countryCode,omitempty"`
	PhoneNumber        string `json:"phoneNumber,omitempty"`
	Address1           string `json:"address1,omitempty"`
	Address2           string `json:"address2,omitempty"`
	Address3           string `json:"address3,omitempty"`
	Locality           string `json:"locality,omitempty"`
	AdministrativeArea string `json:"administrativeArea,omitempty"`
	SortingCode        string `json:"sortingCode,omitempty"`
}
