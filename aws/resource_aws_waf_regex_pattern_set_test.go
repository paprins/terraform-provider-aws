package aws

import (
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/waf"
	"github.com/hashicorp/terraform/helper/acctest"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
)

func TestAccAWSWafRegexPatternSet_basic(t *testing.T) {
	var v waf.ByteMatchSet
	setName := fmt.Sprintf("tfacc-%s", acctest.RandString(5))

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckAWSWafRegexPatternSetDestroy,
		Steps: []resource.TestStep{
			resource.TestStep{
				Config: testAccAWSWafRegexPatternSetConfig(setName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAWSWafRegexPatternSetExists("aws_waf_regex_pattern_set.test", &v),
					resource.TestCheckResourceAttr("aws_waf_regex_pattern_set.test", "name", setName),
					resource.TestCheckResourceAttr("aws_waf_regex_pattern_set.test", "regex_pattern_strings.#", "2"),
					resource.TestCheckResourceAttr("aws_waf_regex_pattern_set.test", "regex_pattern_strings.2174619346", "aaa"),
					resource.TestCheckResourceAttr("aws_waf_regex_pattern_set.test", "regex_pattern_strings.2174619346", "bbb"),
				),
			},
		},
	})
}

func TestAccAWSWafRegexPatternSet_changePatterns(t *testing.T) {
	var before, after waf.ByteMatchSet
	byteMatchSetName := fmt.Sprintf("byteMatchSet-%s", acctest.RandString(5))

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckAWSWafRegexPatternSetDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAWSWafRegexPatternSetConfig(byteMatchSetName),
				Check: resource.ComposeAggregateTestCheckFunc(
					testAccCheckAWSWafRegexPatternSetExists("aws_waf_regex_pattern_set.test", &before),
					resource.TestCheckResourceAttr("aws_waf_regex_pattern_set.test", "name", byteMatchSetName),
					resource.TestCheckResourceAttr("aws_waf_regex_pattern_set.test", "regex_pattern_strings.#", "2"),
					resource.TestCheckResourceAttr("aws_waf_regex_pattern_set.test", "regex_pattern_strings.2174619346.field_to_match.#", "1"),
					resource.TestCheckResourceAttr("aws_waf_regex_pattern_set.test", "regex_pattern_strings.2174619346.field_to_match.2991901334.data", "referer"),
				),
			},
			{
				Config: testAccAWSWafRegexPatternSetConfig_changePatterns(byteMatchSetName),
				Check: resource.ComposeAggregateTestCheckFunc(
					testAccCheckAWSWafRegexPatternSetExists("aws_waf_regex_pattern_set.test", &after),
					resource.TestCheckResourceAttr("aws_waf_regex_pattern_set.test", "name", byteMatchSetName),
					resource.TestCheckResourceAttr("aws_waf_regex_pattern_set.test", "regex_pattern_strings.#", "2"),
					resource.TestCheckResourceAttr("aws_waf_regex_pattern_set.test", "regex_pattern_strings.2174619346.field_to_match.#", "1"),
				),
			},
		},
	})
}

func TestAccAWSWafRegexPatternSet_noPatterns(t *testing.T) {
	var byteSet waf.ByteMatchSet
	byteMatchSetName := fmt.Sprintf("byteMatchSet-%s", acctest.RandString(5))

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckAWSWafRegexPatternSetDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAWSWafRegexPatternSetConfig_noPatterns(byteMatchSetName),
				Check: resource.ComposeAggregateTestCheckFunc(
					testAccCheckAWSWafRegexPatternSetExists("aws_waf_regex_pattern_set.test", &byteSet),
					resource.TestCheckResourceAttr("aws_waf_regex_pattern_set.test", "name", byteMatchSetName),
					resource.TestCheckResourceAttr("aws_waf_regex_pattern_set.test", "regex_pattern_strings.#", "0"),
				),
			},
		},
	})
}

func TestAccAWSWafRegexPatternSet_disappears(t *testing.T) {
	var v waf.ByteMatchSet
	byteMatchSet := fmt.Sprintf("byteMatchSet-%s", acctest.RandString(5))

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckAWSWafRegexPatternSetDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAWSWafRegexPatternSetConfig(byteMatchSet),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAWSWafRegexPatternSetExists("aws_waf_regex_pattern_set.test", &v),
					testAccCheckAWSWafRegexPatternSetDisappears(&v),
				),
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

func testAccCheckAWSWafRegexPatternSetDisappears(v *waf.ByteMatchSet) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		conn := testAccProvider.Meta().(*AWSClient).wafconn

		wr := newWafRetryer(conn, "global")
		_, err := wr.RetryWithToken(func(token *string) (interface{}, error) {
			req := &waf.UpdateByteMatchSetInput{
				ChangeToken:    token,
				ByteMatchSetId: v.ByteMatchSetId,
			}

			for _, ByteMatchTuple := range v.ByteMatchPatterns {
				ByteMatchUpdate := &waf.ByteMatchSetUpdate{
					Action: aws.String("DELETE"),
					ByteMatchTuple: &waf.ByteMatchTuple{
						FieldToMatch:         ByteMatchTuple.FieldToMatch,
						PositionalConstraint: ByteMatchTuple.PositionalConstraint,
						TargetString:         ByteMatchTuple.TargetString,
						TextTransformation:   ByteMatchTuple.TextTransformation,
					},
				}
				req.Updates = append(req.Updates, ByteMatchUpdate)
			}

			return conn.UpdateByteMatchSet(req)
		})
		if err != nil {
			return errwrap.Wrapf("[ERROR] Error updating ByteMatchSet: {{err}}", err)
		}

		_, err = wr.RetryWithToken(func(token *string) (interface{}, error) {
			opts := &waf.DeleteByteMatchSetInput{
				ChangeToken:    token,
				ByteMatchSetId: v.ByteMatchSetId,
			}
			return conn.DeleteByteMatchSet(opts)
		})
		if err != nil {
			return errwrap.Wrapf("[ERROR] Error deleting ByteMatchSet: {{err}}", err)
		}

		return nil
	}
}

func testAccCheckAWSWafRegexPatternSetExists(n string, v *waf.ByteMatchSet) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[n]
		if !ok {
			return fmt.Errorf("Not found: %s", n)
		}

		if rs.Primary.ID == "" {
			return fmt.Errorf("No WAF ByteMatchSet ID is set")
		}

		conn := testAccProvider.Meta().(*AWSClient).wafconn
		resp, err := conn.GetByteMatchSet(&waf.GetByteMatchSetInput{
			ByteMatchSetId: aws.String(rs.Primary.ID),
		})

		if err != nil {
			return err
		}

		if *resp.ByteMatchSet.ByteMatchSetId == rs.Primary.ID {
			*v = *resp.ByteMatchSet
			return nil
		}

		return fmt.Errorf("WAF ByteMatchSet (%s) not found", rs.Primary.ID)
	}
}

func testAccCheckAWSWafRegexPatternSetDestroy(s *terraform.State) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "aws_waf_regex_pattern_set" {
			continue
		}

		conn := testAccProvider.Meta().(*AWSClient).wafconn
		resp, err := conn.GetByteMatchSet(
			&waf.GetByteMatchSetInput{
				ByteMatchSetId: aws.String(rs.Primary.ID),
			})

		if err == nil {
			if *resp.ByteMatchSet.ByteMatchSetId == rs.Primary.ID {
				return fmt.Errorf("WAF ByteMatchSet %s still exists", rs.Primary.ID)
			}
		}

		// Return nil if the ByteMatchSet is already destroyed
		if awsErr, ok := err.(awserr.Error); ok {
			if awsErr.Code() == "WAFNonexistentItemException" {
				return nil
			}
		}

		return err
	}

	return nil
}

func testAccAWSWafRegexPatternSetConfig(name string) string {
	return fmt.Sprintf(`
resource "aws_waf_regex_pattern_set" "test" {
  name = "%s"
  regex_pattern_strings {
    text_transformation = "NONE"
    target_string = "badrefer1"
    positional_constraint = "CONTAINS"
    field_to_match {
      type = "HEADER"
      data = "referer"
    }
  }

  regex_pattern_strings {
    text_transformation = "NONE"
    target_string = "badrefer2"
    positional_constraint = "CONTAINS"
    field_to_match {
      type = "HEADER"
      data = "referer"
    }
  }
}`, name)
}

func testAccAWSWafRegexPatternSetConfigChangeName(name string) string {
	return fmt.Sprintf(`
resource "aws_waf_regex_pattern_set" "test" {
  name = "%s"
  regex_pattern_strings {
    text_transformation = "NONE"
    target_string = "badrefer1"
    positional_constraint = "CONTAINS"
    field_to_match {
      type = "HEADER"
      data = "referer"
    }
  }

  regex_pattern_strings {
    text_transformation = "NONE"
    target_string = "badrefer2"
    positional_constraint = "CONTAINS"
    field_to_match {
      type = "HEADER"
      data = "referer"
    }
  }
}`, name)
}

func testAccAWSWafRegexPatternSetConfig_changePatterns(name string) string {
	return fmt.Sprintf(`
resource "aws_waf_regex_pattern_set" "test" {
  name = "%s"
  regex_pattern_strings {
    text_transformation = "NONE"
    target_string = "badrefer1"
    positional_constraint = "CONTAINS"
    field_to_match {
      type = "HEADER"
      data = "referer"
    }
  }

  regex_pattern_strings {
    text_transformation = "URL_DECODE"
    target_string = "blah"
    positional_constraint = "CONTAINS_WORD"
    field_to_match {
      type = "METHOD"
      data = "GET"
    }
  }
}`, name)
}

func testAccAWSWafRegexPatternSetConfig_noPatterns(name string) string {
	return fmt.Sprintf(`
resource "aws_waf_regex_pattern_set" "test" {
  name = "%s"
}`, name)
}
