package aws

import (
	"fmt"
	"log"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/waf"
	"github.com/hashicorp/terraform/helper/schema"
)

func resourceAwsWafRegexPatternSet() *schema.Resource {
	return &schema.Resource{
		Create: resourceAwsWafRegexPatternSetCreate,
		Read:   resourceAwsWafRegexPatternSetRead,
		Update: resourceAwsWafRegexPatternSetUpdate,
		Delete: resourceAwsWafRegexPatternSetDelete,

		Schema: map[string]*schema.Schema{
			"name": &schema.Schema{
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			"regex_pattern_strings": &schema.Schema{
				Type:     schema.TypeSet,
				Required: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},
		},
	}
}

func resourceAwsWafRegexPatternSetCreate(d *schema.ResourceData, meta interface{}) error {
	conn := meta.(*AWSClient).wafconn

	log.Printf("[INFO] Creating Regex Pattern Set: %s", d.Get("name").(string))

	wr := newWafRetryer(conn, "global")
	out, err := wr.RetryWithToken(func(token *string) (interface{}, error) {
		params := &waf.CreateRegexPatternSetInput{
			ChangeToken: token,
			Name:        aws.String(d.Get("name").(string)),
		}
		return conn.CreateRegexPatternSet(params)
	})
	if err != nil {
		return fmt.Errorf("Failed creating WAF Regex Pattern Set: %s", err)
	}
	resp := out.(*waf.CreateRegexPatternSetOutput)

	d.SetId(*resp.RegexPatternSet.RegexPatternSetId)

	return resourceAwsWafRegexPatternSetUpdate(d, meta)
}

func resourceAwsWafRegexPatternSetRead(d *schema.ResourceData, meta interface{}) error {
	conn := meta.(*AWSClient).wafconn
	log.Printf("[INFO] Reading Regex Pattern Set: %s", d.Get("name").(string))
	params := &waf.GetRegexPatternSetInput{
		RegexPatternSetId: aws.String(d.Id()),
	}

	resp, err := conn.GetRegexPatternSet(params)
	if err != nil {
		if isAWSErr(err, "WAFNonexistentItemException", "") {
			log.Printf("[WARN] WAF Regex Pattern Set (%s) not found, removing from state", d.Id())
			d.SetId("")
			return nil
		}

		return err
	}

	d.Set("name", resp.RegexPatternSet.Name)
	d.Set("regex_pattern_strings", aws.StringValueSlice(resp.RegexPatternSet.RegexPatternStrings))

	return nil
}

func resourceAwsWafRegexPatternSetUpdate(d *schema.ResourceData, meta interface{}) error {
	conn := meta.(*AWSClient).wafconn

	log.Printf("[INFO] Updating Regex Pattern Set: %s", d.Get("name").(string))

	if d.HasChange("regex_pattern_strings") {
		o, n := d.GetChange("regex_pattern_strings")
		oldT, newT := o.(*schema.Set).List(), n.(*schema.Set).List()
		err := updateWafRegexPatternSetPatternStrings(d.Id(), oldT, newT, conn)
		if err != nil {
			return fmt.Errorf("Failed updating WAF Regex Pattern Set: %s", err)
		}
	}

	return resourceAwsWafRegexPatternSetRead(d, meta)
}

func resourceAwsWafRegexPatternSetDelete(d *schema.ResourceData, meta interface{}) error {
	conn := meta.(*AWSClient).wafconn

	oldTuples := d.Get("regex_pattern_strings").(*schema.Set).List()
	if len(oldTuples) > 0 {
		noTuples := []interface{}{}
		err := updateWafRegexPatternSetPatternStrings(d.Id(), oldTuples, noTuples, conn)
		if err != nil {
			return fmt.Errorf("Error updating Regex Pattern Set: %s", err)
		}
	}

	wr := newWafRetryer(conn, "global")
	_, err := wr.RetryWithToken(func(token *string) (interface{}, error) {
		req := &waf.DeleteRegexPatternSetInput{
			ChangeToken:       token,
			RegexPatternSetId: aws.String(d.Id()),
		}
		log.Printf("[INFO] Deleting WAF Regex Pattern Set: %s", req)
		return conn.DeleteRegexPatternSet(req)
	})
	if err != nil {
		return fmt.Errorf("Failed deleting WAF Regex Pattern Set: %s", err)
	}

	return nil
}

func updateWafRegexPatternSetPatternStrings(id string, oldT, newT []interface{}, conn *waf.WAF) error {
	wr := newWafRetryer(conn, "global")
	_, err := wr.RetryWithToken(func(token *string) (interface{}, error) {
		req := &waf.UpdateRegexPatternSetInput{
			ChangeToken:       token,
			RegexPatternSetId: aws.String(id),
			Updates:           diffWafRegexPatternSetPatternStrings(oldT, newT),
		}

		return conn.UpdateRegexPatternSet(req)
	})
	if err != nil {
		return fmt.Errorf("Failed updating WAF Regex Pattern Set: %s", err)
	}

	return nil
}

func diffWafRegexPatternSetPatternStrings(oldPatterns, newPatterns []interface{}) []*waf.RegexPatternSetUpdate {
	updates := make([]*waf.RegexPatternSetUpdate, 0)

	for _, op := range oldPatterns {
		if idx, contains := sliceContainsString(newPatterns, op.(string)); contains {
			newPatterns = append(newPatterns[:idx], newPatterns[idx+1:]...)
			continue
		}

		updates = append(updates, &waf.RegexPatternSetUpdate{
			Action:             aws.String(waf.ChangeActionDelete),
			RegexPatternString: aws.String(op.(string)),
		})
	}

	for _, np := range newPatterns {
		updates = append(updates, &waf.RegexPatternSetUpdate{
			Action:             aws.String(waf.ChangeActionInsert),
			RegexPatternString: aws.String(np.(string)),
		})
	}
	return updates
}

func sliceContainsString(slice []interface{}, s string) (int, bool) {
	for idx, value := range slice {
		v := value.(string)
		if v == s {
			return idx, true
		}
	}
	return -1, false
}
